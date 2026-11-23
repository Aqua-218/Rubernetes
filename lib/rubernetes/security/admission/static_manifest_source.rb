# frozen_string_literal: true

require "digest"
require "fiddle"
require "pathname"
require "uri"
require "yaml"

module Rubernetes
  module Security
    module Admission
      # Manifest-based admission is independent of registry storage. A plugin
      # sees one complete snapshot of its directory, and a bad reload leaves
      # its last validated snapshot in service.
      class StaticManifestSource
        GATE = "ManifestBasedAdmissionControlConfig"
        GROUP = "admissionregistration.k8s.io"
        API_VERSION = "#{GROUP}/v1".freeze
        SUFFIX = ".static.k8s.io"
        RESERVED_NAME = "names ending with #{SUFFIX.inspect} are reserved for static manifest-based configurations and cannot be managed via the API".freeze
        PLUGINS = {
          "MutatingAdmissionWebhook" => %w[MutatingWebhookConfiguration].freeze,
          "ValidatingAdmissionWebhook" => %w[ValidatingWebhookConfiguration].freeze,
          "MutatingAdmissionPolicy" => %w[MutatingAdmissionPolicy MutatingAdmissionPolicyBinding].freeze,
          "ValidatingAdmissionPolicy" => %w[ValidatingAdmissionPolicy ValidatingAdmissionPolicyBinding].freeze
        }.freeze
        KINDS = PLUGINS.values.flatten.freeze
        RESOURCE_BY_KIND = KINDS.to_h do |kind|
          [kind, kind.end_with?("Policy") ? "#{kind.downcase.delete_suffix("y")}ies" : "#{kind.downcase}s"]
        end.freeze
        RESOURCES = RESOURCE_BY_KIND.values.freeze
        POLL_INTERVAL = 60
        RELOADS = "apiserver_manifest_admission_config_controller_automatic_reloads_total"
        TIMESTAMP = "apiserver_manifest_admission_config_controller_automatic_reload_last_timestamp_seconds"
        CONFIG_INFO = "apiserver_manifest_admission_config_controller_last_config_info"
        INOTIFY_WATCH_MASK = 0x00000fcc # ATTRIB, CLOSE_WRITE, moves, creates and deletes.
        INOTIFY_WATCH_LOST = 0x00008c00 # DELETE_SELF, MOVE_SELF and IGNORED.
        MATCH_DEFAULTS = {"matchPolicy" => "Equivalent", "namespaceSelector" => {}.freeze, "objectSelector" => {}.freeze}.freeze
        WEBHOOK_DEFAULTS = MATCH_DEFAULTS.merge("failurePolicy" => "Fail", "timeoutSeconds" => 10).freeze

        attr_accessor :metrics
        attr_reader :snapshot

        def initialize(plugin:, path:, feature_enabled:, apiserver_id:, logger: nil, clock: -> { Time.now.utc }, interval: POLL_INTERVAL)
          raise ConfigurationError, "staticManifestsDir requires the #{GATE} feature gate to be enabled" unless feature_enabled
          unless path.is_a?(String) && Pathname.new(path).absolute? && File.directory?(path)
            raise ConfigurationError, "#{plugin} staticManifestsDir must be an existing absolute directory: #{path.inspect}"
          end

          @plugin = plugin
          @kinds = PLUGINS.fetch(plugin)
          @path = path
          @logger = logger
          @clock = clock
          @interval = interval
          identity = apiserver_id.to_s
          @labels = {"plugin" => plugin, "apiserver_id_hash" => identity.empty? ? "" : "sha256:#{Digest::SHA256.hexdigest(identity)}"}.freeze
          @mutex = Mutex.new
          @reload_mutex = Mutex.new
          @snapshot, @hash = load_snapshot
        end

        def start
          @mutex.synchronize do
            return self if @thread&.alive?

            @stop_writer&.close
            stop_reader, @stop_writer = IO.pipe
            @thread = Thread.new do
              Thread.current.name = "#{@plugin}-manifest-reload"
              watch_directory(stop_reader)
            end
          end
          self
        end

        def stop
          thread = @mutex.synchronize do
            @stop_writer&.close
            @stop_writer = nil
            @thread
          end
          thread&.join(2)
          self
        end

        def check!
          @reload_mutex.synchronize do
            updated, hash = load_snapshot
            return false if hash == @hash

            previous = @hash
            @snapshot = updated
            @hash = hash
            @metrics&.delete(CONFIG_INFO, @labels.merge("hash" => previous))
            record_reload("success")
            record_active_configuration
            true
          rescue ConfigurationError => error
            @logger&.warn("#{@plugin} static manifests in #{@path.inspect} could not be reloaded: #{error.message}")
            record_reload("failure")
            false
          end
        end

        def note_loaded
          return self unless @metrics

          @metrics.register(RELOADS, type: :counter, labels: %w[status plugin apiserver_id_hash],
                                     help: "[ALPHA] Total number of automatic reloads of admission manifest configuration split by status, plugin, " \
                                           "and apiserver identity.")
          @metrics.register(TIMESTAMP, type: :gauge, labels: %w[status plugin apiserver_id_hash],
                                       help: "[ALPHA] Timestamp of the last automatic reload of admission manifest configuration split by status, " \
                                             "plugin, and apiserver identity.")
          @metrics.register(CONFIG_INFO, type: :gauge, labels: %w[plugin apiserver_id_hash hash],
                                         help: "[ALPHA] Information about the last applied admission manifest configuration with hash as label, " \
                                               "split by plugin and apiserver identity.")
          record_reload("success")
          record_active_configuration
          self
        end

        private

        def watch_directory(stop_reader)
          watcher = open_directory_watch
          check! if watcher
          loop do
            ready = IO.select([stop_reader, watcher].compact, nil, nil, @interval)&.first
            break if ready&.include?(stop_reader)

            if ready&.include?(watcher) && inotify_watch_lost?(watcher)
              watcher.close
              watcher = nil
            end
            watcher ||= open_directory_watch
            check!
          end
        ensure
          watcher&.close
          stop_reader.close
        end

        def open_directory_watch
          return unless RUBY_PLATFORM.include?("linux")

          symbols = Fiddle::Handle::DEFAULT
          init = Fiddle::Function.new(symbols["inotify_init1"], [Fiddle::TYPE_INT], Fiddle::TYPE_INT)
          add = Fiddle::Function.new(symbols["inotify_add_watch"], [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_INT)
          fd = init.call(File::NONBLOCK)
          return if fd.negative?

          io = IO.for_fd(fd)
          io.close_on_exec = true
          return io unless add.call(fd, Fiddle::Pointer["#{@path}\0"], INOTIFY_WATCH_MASK).negative?

          io.close
          nil
        rescue Fiddle::DLError
          nil
        end

        def inotify_watch_lost?(watcher)
          bytes = watcher.read_nonblock(65_536, exception: false)
          return false unless bytes.is_a?(String)

          offset = 0
          while offset < bytes.bytesize
            _watch, mask, _cookie, name_length = bytes.unpack("L4", offset: offset)
            return true unless mask.nobits?(INOTIFY_WATCH_LOST)

            offset += 16 + name_length
          end
          false
        end

        def record_reload(status)
          labels = @labels.merge("status" => status)
          @metrics&.increment(RELOADS, labels)
          @metrics&.set(TIMESTAMP, @clock.call.to_f, labels)
        end

        def record_active_configuration
          @metrics&.set(CONFIG_INFO, 1, @labels.merge("hash" => @hash))
        end

        def load_snapshot
          digest = Digest::SHA256.new
          any_bytes = false
          objects = @kinds.to_h { |kind| [kind, {}] }
          Dir.children(@path).sort.each do |entry|
            file = File.join(@path, entry)
            next if File.lstat(file).directory? || !%w[.yaml .yml .json].include?(File.extname(entry).downcase)

            bytes = File.binread(file)
            next if bytes.empty?

            digest << bytes << "\0"
            any_bytes = true
            load_file(file, bytes, objects)
          end
          verify_bindings(objects)
          snapshot = objects.to_h do |kind, entries|
            [RESOURCE_BY_KIND.fetch(kind), entries.keys.sort.map { |name| entries.fetch(name) }.freeze]
          end.freeze
          [snapshot, any_bytes ? "sha256:#{digest.hexdigest}" : ""]
        rescue SystemCallError => error
          raise ConfigurationError, "loading #{@plugin} static manifests from #{@path.inspect}: #{error.message}"
        end

        def load_file(file, bytes, objects)
          loader = Psych::ClassLoader::Restricted.new([], [])
          visitor = Psych::Visitors::NoAliasRuby.new(Psych::ScalarScanner.new(loader), loader)
          YAML.parse_stream(bytes, filename: file).children.each do |document|
            root = document.root
            next if root.nil? || (root.is_a?(Psych::Nodes::Scalar) && root.value.empty? && root.plain)

            validate_unique_keys(root)
            object = visitor.accept(root)
            unpack(object).each { |item| add_item(item, objects) }
          end
        rescue Psych::Exception, ConfigurationError, TypeError => error
          raise ConfigurationError, "error loading #{file}: #{error.message}"
        end

        def validate_unique_keys(root)
          pending = [root]
          until pending.empty?
            node = pending.pop
            pending.concat(node.children || [])
            next unless node.is_a?(Psych::Nodes::Mapping)

            keys = node.children.each_slice(2).map { |key, _value| key.value if key.is_a?(Psych::Nodes::Scalar) }
            duplicates = keys.compact.tally.select { |_key, count| count > 1 }.keys
            raise ConfigurationError, "duplicate field #{duplicates.first.inspect}" unless duplicates.empty?
          end
        end

        def unpack(object, parent_kind: nil)
          raise ConfigurationError, "expected a Kubernetes object" unless object.is_a?(Hash)

          kind = object["kind"] || parent_kind
          version = object["apiVersion"] || (API_VERSION if parent_kind)
          return list_items(object).flat_map { |item| unpack(item) } if kind == "List" && version == "v1"
          if version == API_VERSION && kind.to_s.end_with?("List") && @kinds.include?(kind.delete_suffix("List"))
            return list_items(object).flat_map { |item| unpack(item, parent_kind: kind.delete_suffix("List")) }
          end
          unless version == API_VERSION && @kinds.include?(kind) && (parent_kind.nil? || parent_kind == kind)
            raise ConfigurationError, "unsupported resource type #{version} #{kind} for #{@plugin}"
          end

          [object.merge("apiVersion" => version, "kind" => kind)]
        end

        def list_items(object)
          items = object.fetch("items", [])
          raise ConfigurationError, "items must be a list" unless items.is_a?(Array)

          items
        end

        def add_item(item, objects)
          kind = item.fetch("kind")
          name = item.dig("metadata", "name")
          raise ConfigurationError, "#{kind} must have a name ending with #{SUFFIX.inspect}" unless name.is_a?(String) && name.end_with?(SUFFIX)
          raise ConfigurationError, "duplicate name #{name.inspect}" if objects.fetch(kind).key?(name)

          validate_static_constraints(item, kind, name)
          definition = manifest_definition(kind)
          defaulted = definition.defaulting.apply_hash(apply_static_defaults(item), unknown_fields: :preserve, kubernetes_admission_defaults: true)
          errors = definition.validator.errors(defaulted, unknown_fields: :reject, operation: :create)
          unless errors.empty?
            issues = errors.map { |issue| issue.to_cause(defaulted) }.map { |cause| "#{cause["field"]}: #{cause["message"]}" }
            raise ConfigurationError, "#{kind} #{name.inspect}: #{issues.join(", ")}"
          end

          objects.fetch(kind)[name] = deep_freeze(defaulted)
        end

        def manifest_definition(kind)
          require File.expand_path("../../../../generated/ruby/kubernetes_types", __dir__)
          Generated.const_get("IoK8sApiAdmissionregistrationV1#{kind}", false)::DEFINITION
        end

        def apply_static_defaults(item)
          if item["webhooks"].is_a?(Array)
            defaults = item["kind"] == "MutatingWebhookConfiguration" ? WEBHOOK_DEFAULTS.merge("reinvocationPolicy" => "Never") : WEBHOOK_DEFAULTS
            item["webhooks"] = item["webhooks"].map do |hook|
              next hook unless hook.is_a?(Hash)

              hook = defaults.merge(hook.reject { |key, value| value.nil? && defaults.key?(key) })
              hook["rules"] = default_rule_scope(hook["rules"]) if hook["rules"].is_a?(Array)
              hook
            end
          elsif (spec = item["spec"]).is_a?(Hash)
            binding = item["kind"].end_with?("Binding")
            spec["failurePolicy"] ||= "Fail" unless binding
            key = binding ? "matchResources" : "matchConstraints"
            if (match = spec[key]).is_a?(Hash)
              spec[key] = MATCH_DEFAULTS.merge(match.reject { |field, value| value.nil? && MATCH_DEFAULTS.key?(field) })
              %w[resourceRules excludeResourceRules].each do |rule_key|
                spec[key][rule_key] = default_rule_scope(match[rule_key]) if match[rule_key].is_a?(Array)
              end
            end
          end
          item
        end

        def default_rule_scope(rules)
          rules.map { |rule| rule.is_a?(Hash) && rule["scope"].nil? ? rule.merge("scope" => "*") : rule }
        end

        def validate_static_constraints(item, kind, name)
          if kind.end_with?("WebhookConfiguration")
            validate_webhook_constraints(item, name)
          elsif kind.end_with?("Binding")
            policy_name = item.dig("spec", "policyName")
            unless policy_name.is_a?(String) && policy_name.end_with?(SUFFIX)
              raise ConfigurationError, "binding #{name.inspect}: spec.policyName must end with #{SUFFIX.inspect}"
            end
            raise ConfigurationError, "binding #{name.inspect}: spec.paramRef is not supported for static manifests" if item.dig("spec", "paramRef")
          elsif item.dig("spec", "paramKind")
            raise ConfigurationError, "#{kind} #{name.inspect}: spec.paramKind is not supported for static manifests"
          end
        end

        def validate_webhook_constraints(item, name)
          seen = {}
          Array(item["webhooks"]).grep(Hash).each do |hook|
            hook_name = hook["name"]
            context = "webhook #{hook_name.inspect} in #{name.inspect}"
            raise ConfigurationError, "#{context}: duplicate webhook name" if seen[hook_name]

            seen[hook_name] = true
            raise ConfigurationError, "#{context}: clientConfig.service is not supported for static manifests" if hook.dig("clientConfig", "service")

            url = hook.dig("clientConfig", "url")
            raise ConfigurationError, "#{context}: clientConfig.url is required for static manifests" if url.to_s.empty?
            raise ConfigurationError, "#{context}: clientConfig.url must be a valid https://host[/path] URL" unless webhook_url?(url)

            timeout = hook["timeoutSeconds"]
            raise ConfigurationError, "#{context}: timeoutSeconds must be between 1 and 30" if timeout && (!timeout.is_a?(Integer) || !timeout.between?(1, 30))
          end
        end

        def webhook_url?(value)
          return false unless value.is_a?(String)

          uri = URI.parse(value)
          uri.scheme == "https" && !uri.host.to_s.empty? && uri.userinfo.nil? && uri.query.to_s.empty? && uri.fragment.to_s.empty?
        rescue URI::InvalidURIError
          false
        end

        def verify_bindings(objects)
          return unless @kinds.length == 2

          policies, bindings = @kinds.map { |kind| objects.fetch(kind) }
          bindings.each do |name, binding|
            policy = binding.dig("spec", "policyName")
            next if policies.key?(policy)

            raise ConfigurationError, "binding #{name.inspect} references policy #{policy.inspect} which does not exist in the manifest directory"
          end
        end

        def deep_freeze(object)
          case object
          when Hash then object.each_value { |value| deep_freeze(value) }
          when Array then object.each { |value| deep_freeze(value) }
          end
          object.freeze
        end
      end
    end
  end
end
