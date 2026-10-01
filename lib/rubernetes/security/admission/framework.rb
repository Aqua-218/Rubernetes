# frozen_string_literal: true

require "json"
require "securerandom"

require_relative "../identity"

module Rubernetes
  module Security
    module Admission
      OPERATIONS = %w[CREATE UPDATE DELETE CONNECT].freeze

      class Error < Security::Error; end

      # apiequality.Semantic.DeepEqual over decoded objects: the forked
      # reflect comparison treats a nil and an empty map or slice as equal,
      # which for JSON documents means an absent member, a null and an
      # empty object or array compare equal.
      def self.semantically_equal?(left, right)
        semantic_form(left) == semantic_form(right)
      end

      def self.semantic_form(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, item), out|
            form = semantic_form(item)
            out[key.to_s] = form unless form.nil?
          end.then { |hash| hash.empty? ? nil : hash }
        when Array
          value.empty? ? nil : value.map { |item| semantic_form(item) }
        else
          value
        end
      end

      # Rejection carrying a Status-shaped reason (mapped to 4xx by the API).
      class Rejected < Error
        attr_reader :code, :reason, :details, :plugin

        def initialize(message, code: 403, reason: "Forbidden", details: nil, plugin: nil)
          @code = code
          @reason = reason
          @details = details
          @plugin = plugin
          super(message)
        end
      end

      # Attributes for one admission decision (k8s.io/apiserver/pkg/admission Attributes).
      class Attributes
        attr_reader :operation, :user, :namespace, :name, :group, :version, :resource, :subresource, :kind, :old_object, :dry_run,
                    :options, :warnings, :annotations
        attr_accessor :object

        def initialize(operation:, user:, group:, version:, resource:, kind:, subresource: "", namespace: "", name: "", object: nil,
                       old_object: nil, dry_run: false, options: nil)
          @operation = operation.to_s.upcase
          raise ArgumentError, "unknown admission operation #{operation}" unless OPERATIONS.include?(@operation)

          @user = user
          @group = group.to_s
          @version = version.to_s
          @resource = resource.to_s
          @kind = kind.to_s
          @subresource = subresource.to_s
          @namespace = namespace.nil? || namespace == :cluster || namespace == :all ? "" : namespace.to_s
          @name = name.to_s
          @object = object
          @old_object = old_object
          @dry_run = dry_run == true
          @options = options
          @warnings = []
          @annotations = {}
          @reinvocation = false
        end

        def api_version
          @group.empty? ? @version : "#{@group}/#{@version}"
        end

        def gvr
          [@group, @version, @resource]
        end

        def gvk
          [@group, @version, @kind]
        end

        def warn(message)
          @warnings << message.to_s
        end

        # The admission request's UID, shared by every webhook and policy of
        # one request (AdmissionReview.request.uid).
        def uid
          @uid ||= SecureRandom.uuid
        end

        def annotate(key, value)
          @annotations[key.to_s] = value.to_s
        end

        # ReinvocationContext (admission/attributes.go): IsReinvoke while the
        # chain runs its second pass, ShouldReinvoke once a reinvocable
        # plugin asked for that pass, and per-plugin state values.
        def reinvocation?
          @reinvocation
        end

        def mark_reinvocation!
          @reinvocation = true
        end

        def reinvoke_requested?
          @reinvoke_requested == true
        end

        def request_reinvocation!
          @reinvoke_requested = true
        end

        def reinvocation_value(plugin)
          (@reinvocation_values ||= {})[plugin]
        end

        def set_reinvocation_value(plugin, value)
          (@reinvocation_values ||= {})[plugin] = value
        end

        def subresource?
          !@subresource.empty?
        end
      end

      # Plugin base: handles?(operation) decides applicability; admit mutates,
      # validate rejects.  Plugins receive a `context` giving store access
      # (namespaces, quotas, limit ranges, storage classes, runtime classes,
      # service accounts, secrets, priority classes, ingress classes).
      class Plugin
        attr_reader :name
        # The API server's registry (apiserver_admission_* metrics).
        attr_accessor :metrics

        def initialize(name, context: nil, config: {})
          @name = name
          @context = context
          @config = config || {}
        end

        def mutating? = respond_to?(:admit)
        def validating? = respond_to?(:validate)

        def handles?(_attributes)
          true
        end

        # Reinvokable plugins (e.g. webhooks, policies) may be called again
        # after another mutating plugin changed the object.
        def reinvokable?
          false
        end
      end

      # Ordered chain (pkg/kubeapiserver/options/plugins.go AllOrderedPlugins).
      # Mutating admission runs first in plugin order; validating admission
      # runs afterwards on the final object.  The reinvoker
      # (admission/reinvocation.go) runs the whole mutating chain -- in-tree
      # plugins included -- exactly once more when a reinvocable plugin
      # (webhook or policy) requested it; the plugins themselves decide which
      # of their hooks run on that pass.
      class Chain
        attr_reader :plugins, :metrics

        STEP_BUCKETS = [0.005, 0.025, 0.1, 0.5, 1.0, 2.5].freeze
        WEBHOOK_BUCKETS = [0.005, 0.025, 0.1, 0.5, 1.0, 2.5, 10, 25].freeze

        def initialize(plugins:)
          @plugins = plugins
          @metrics = nil
        end

        # admission/metrics: the step, controller and webhook families.
        def metrics=(registry)
          @metrics = registry
          return unless registry

          registry.register("apiserver_admission_step_admission_duration_seconds", type: :histogram, buckets: STEP_BUCKETS,
                                                                                   help: "Admission sub-step latency histogram in seconds, broken out for " \
                                                                                         "each operation and API resource and step type (validate or admit).")
          registry.register("apiserver_admission_controller_admission_duration_seconds", type: :histogram, buckets: STEP_BUCKETS,
                                                                                         help: "Admission controller latency histogram in seconds, " \
                                                                                               "identified by name and broken out for each operation and " \
                                                                                               "API resource and type (validate or admit).")
          registry.register("apiserver_admission_webhook_admission_duration_seconds", type: :histogram, buckets: WEBHOOK_BUCKETS,
                                                                                      help: "Admission webhook latency histogram in seconds, identified by " \
                                                                                            "name and broken out for each operation and API resource and " \
                                                                                            "type (validate or admit).")
          registry.register("apiserver_admission_webhook_rejection_count", type: :counter,
                                                                           help: "Admission webhook rejection count, identified by name and broken out for " \
                                                                                 "each admission type (validating or admit) and operation.")
          registry.register("apiserver_admission_webhook_fail_open_count", type: :counter,
                                                                           help: "Admission webhook fail open count, identified by name and broken out for " \
                                                                                 "each admission type (validating or admit).")
          registry.register("apiserver_admission_webhook_request_total", type: :counter,
                                                                         help: "Admission webhook request total, identified by name and broken out for each " \
                                                                               "admission type (validating or admit) and operation.")
          @plugins.each { |plugin| plugin.metrics = registry if plugin.respond_to?(:metrics=) }
        end

        def names
          @plugins.map(&:name)
        end

        # Mutating phase; returns the final object.
        def admit(attributes)
          return attributes.object if @plugins.empty?

          step(attributes, "admit") { admit_plugins(attributes) }
        end

        def admit_plugins(attributes)
          run_mutators(attributes)
          if attributes.reinvoke_requested?
            attributes.mark_reinvocation!
            run_mutators(attributes)
          end
          attributes.object
        end

        # Validating phase; raises Rejected on the first failure.
        def validate(attributes)
          step(attributes, "validate") do
            @plugins.each do |plugin|
              next unless plugin.validating? && plugin.handles?(attributes)

              timed(plugin, attributes, "validate") { plugin.validate(attributes) }
            end
          end
          true
        end

        private

        # chainAdmissionHandler.Admit: every mutating plugin that handles the
        # request, in order.
        def run_mutators(attributes)
          @plugins.each do |plugin|
            next unless plugin.mutating? && plugin.handles?(attributes)

            timed(plugin, attributes, "admit") { plugin.admit(attributes) }
          end
        end

        # ObserveAdmissionStep: the whole phase, rejected or not.
        def step(attributes, type)
          return yield unless @metrics

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          rejected = false
          begin
            yield
          rescue Rejected
            rejected = true
            raise
          ensure
            labels = {"type" => type, "operation" => operation(attributes), "rejected" => rejected.to_s}
            observe("apiserver_admission_step_admission_duration_seconds", started, labels)
            # The deprecated summary twin (ALPHA, still registered in v1.36).
            observe("apiserver_admission_step_admission_duration_seconds_summary", started, labels)
          end
        end

        def observe(name, started, labels)
          @metrics.observe(name, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, labels)
        rescue StandardError
          nil
        end

        def operation(attributes)
          attributes.respond_to?(:operation) ? attributes.operation.to_s : ""
        end

        # Per-request phase accounting (API::Server request tracing): the time
        # each plugin took, so a slow admission chain names its slow plugin.
        def timed(plugin, attributes = nil, type = nil)
          phases = Thread.current[:rubernetes_request_phases]
          return yield unless phases || @metrics

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          rejected = false
          begin
            yield
          rescue Rejected
            rejected = true
            raise
          ensure
            if phases
              key = "plugin.#{plugin.name}"
              phases[key] = phases.fetch(key, 0.0) + (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
            end
            # ObserveAdmissionController.
            if @metrics && type
              observe("apiserver_admission_controller_admission_duration_seconds", started,
                      {"name" => plugin.name.to_s, "type" => type, "operation" => operation(attributes), "rejected" => rejected.to_s})
            end
          end
        end
      end

      # Store-facing context for plugins.  Every lookup goes through the
      # Store contract so admission never bypasses storage semantics.
      class Context
        def initialize(store:, key_for:, clock: -> { Time.now.utc }, feature_gates: {}, authorizer: nil, resource_resolver: nil,
                       namespace_creator: nil, cel: nil, scope_resolver: nil, type_resolver: nil, defaulter: nil)
          @defaulter = defaulter
          @scope_resolver = scope_resolver
          @type_resolver = type_resolver
          @store = store
          @key_for = key_for
          @clock = clock
          @feature_gates = feature_gates
          @authorizer = authorizer
          @resource_resolver = resource_resolver
          @namespace_creator = namespace_creator
          @cel = cel
        end

        attr_reader :clock, :feature_gates, :authorizer, :cel

        # Kind -> plural resource through the API registry.
        def resource_for_kind(group, kind)
          resolved = @resource_resolver&.call(group, kind)
          resolved || "#{kind.to_s.downcase}s"
        end

        # Whether group/resource is cluster-scoped (a policy's paramKind).
        def cluster_scoped?(group, resource)
          @scope_resolver&.call(group, resource) == true
        end

        # [model, type_ref] of a kind for structured merges, or nil.
        def type_for(group, version, kind)
          @type_resolver&.call(group, version, kind)
        end

        # The scheme defaulter (ObjectInterfaces.GetObjectDefaulter) a
        # MutatingAdmissionPolicy runs over every patched object; identity
        # when the API server supplied none.
        def default_object(group, version, kind, object)
          return object unless @defaulter

          @defaulter.call(group, version, kind, object) || object
        end

        def create_namespace(name)
          @namespace_creator&.call(name)
        end

        def random_suffix
          SecureRandom.alphanumeric(5).downcase
        end

        def get(resource, namespace, name, group: "", version: "v1")
          @store.get(@key_for.call(group, version, resource, namespace, name))
        rescue StandardError
          nil
        end

        def list(resource, namespace = nil, group: "", version: "v1")
          list!(resource, namespace, group: group, version: version)
        rescue StandardError
          []
        end

        # Like #list, but a store failure propagates.  A plugin whose decision
        # depends on what is stored -- quota -- must fail closed: answering
        # "no quotas" to a lookup that failed admitted Pods past their quota.
        def list!(resource, namespace = nil, group: "", version: "v1")
          prefix = @key_for.call(group, version, resource, namespace, nil)
          @store.list(prefix).items
        end

        # A precondition write of one stored object; raises the store's
        # Conflict when `resource_version` is stale.
        def update(resource, namespace, name, object, resource_version:, group: "", version: "v1")
          @store.update(@key_for.call(group, version, resource, namespace, name), object, resource_version: resource_version)
        end

        def namespace(name) = get("namespaces", nil, name)
        def feature_enabled?(gate) = @feature_gates.fetch(gate.to_s, false) == true
      end
    end
  end
end
