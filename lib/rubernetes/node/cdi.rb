# frozen_string_literal: true

require "json"
require "psych"
require_relative "../runtime/native/hooks"

module Rubernetes
  module Node
    # Container Device Interface (tags.cncf.io/container-device-interface):
    # the CDI device IDs a DRA driver returns from NodePrepareResources
    # ("vendor.com/class=name") resolved against the spec files in the CDI
    # directories (JSON or YAML; /etc/cdi then /var/run/cdi -- a device in a
    # later directory takes precedence) into container edits: environment
    # variables, device nodes, mounts, hooks and additional GIDs.  A
    # spec's own containerEdits apply to each of its devices, before the
    # device's.  An ID that no spec defines fails the container
    # ("unresolvable CDI devices ...").
    #
    # The native runtime applies the edits through the container spec:
    # environment variables are set (replacing a value of the same name),
    # mounts and device nodes become bind mounts of the host paths (the
    # device node bind is what runc does in a user namespace), hooks run at
    # their OCI stage with the state on stdin (Runtime::Native::Hooks).
    module CDI
      DEFAULT_SPEC_DIRS = %w[/etc/cdi /var/run/cdi].freeze
      KIND = %r{\A[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]/[A-Za-z0-9][A-Za-z0-9_.-]*[A-Za-z0-9]\z}
      NAME = /\A[A-Za-z0-9][A-Za-z0-9_.:-]*\z/

      class Error < StandardError; end

      Edits = Struct.new(:env, :device_nodes, :mounts, :hooks, :additional_gids, keyword_init: true) do
        def self.empty = new(env: [], device_nodes: [], mounts: [], hooks: [], additional_gids: [])

        def merge!(edits)
          return self unless edits.is_a?(Hash)

          Array(edits["env"]).each do |entry|
            name, value = entry.to_s.split("=", 2)
            env.reject! { |existing| existing[0] == name }
            env << [name, value.to_s]
          end
          Array(edits["deviceNodes"]).each do |node|
            device_nodes.reject! { |existing| existing["path"] == node["path"] }
            device_nodes << node
          end
          mounts.concat(Array(edits["mounts"]))
          hooks.concat(Array(edits["hooks"]))
          additional_gids.concat(Array(edits["additionalGids"]).map { |gid| Integer(gid) })
          self
        end

        def empty? = env.empty? && device_nodes.empty? && mounts.empty? && hooks.empty? && additional_gids.empty?
      end

      module_function

      # "vendor.com/class=name" => ["vendor.com/class", "name"].
      def parse_id(id)
        kind, name = id.to_s.split("=", 2)
        raise Error, "invalid CDI device name #{id.to_s.dump}" if name.nil? || !KIND.match?(kind.to_s) || !NAME.match?(name)

        [kind, name]
      end

      # {"vendor.com/class" => {name => [spec, device]}} from +spec_dirs+.
      def registry(spec_dirs = DEFAULT_SPEC_DIRS)
        devices = {}
        Array(spec_dirs).each do |directory|
          next unless File.directory?(directory)

          found = {}
          Dir.children(directory).sort.each do |file|
            next unless file.end_with?(".json", ".yaml", ".yml")

            path = File.join(directory, file)
            spec = load_spec(path)
            kind = spec["kind"].to_s
            raise Error, "#{path}: invalid CDI kind #{kind.dump}" unless KIND.match?(kind)

            Array(spec["devices"]).each do |device|
              name = device["name"].to_s
              raise Error, "#{path}: invalid CDI device name #{name.dump}" unless NAME.match?(name)

              key = [kind, name]
              raise Error, "conflicting device #{kind}=#{name} (specs #{found[key]}, #{path})" if found.key?(key)

              found[key] = path
              (devices[kind] ||= {})[name] = [spec, device]
            end
          end
        end
        devices
      end

      def load_spec(path)
        text = File.read(path)
        spec = path.end_with?(".json") ? JSON.parse(text) : Psych.safe_load(text, aliases: false)
        raise Error, "#{path}: CDI spec must be an object" unless spec.is_a?(Hash)
        raise Error, "#{path}: missing cdiVersion" if spec["cdiVersion"].to_s.empty?

        spec
      rescue JSON::ParserError, Psych::Exception => error
        raise Error, "#{path}: #{error.message}"
      end

      # The container edits for +ids+.
      def resolve(ids, spec_dirs: DEFAULT_SPEC_DIRS)
        ids = Array(ids).map(&:to_s).uniq
        return Edits.empty if ids.empty?

        devices = registry(spec_dirs)
        unresolved = []
        edits = Edits.empty
        applied_specs = {}.compare_by_identity
        ids.each do |id|
          kind, name = parse_id(id)
          spec, device = devices.dig(kind, name)
          if device.nil?
            unresolved << id
            next
          end
          unless applied_specs.key?(spec)
            edits.merge!(spec["containerEdits"])
            applied_specs[spec.object_id] = true
          end
          edits.merge!(device["containerEdits"])
        end
        raise Error, "unresolvable CDI devices #{unresolved.join(", ")}" unless unresolved.empty?

        edits
      end

      # Apply +edits+ to a container definition built by ContainerSpec.
      def apply(definition, edits)
        return definition if edits.nil? || edits.empty?

        env = Array(definition["env"]).map(&:dup)
        edits.env.each do |name, value|
          env.reject! { |entry| entry["name"] == name }
          env << {"name" => name, "value" => value}
        end
        definition["env"] = env
        mounts = Array(definition["mounts"]).dup
        edits.mounts.each_with_index do |mount, index|
          options = Array(mount["options"]).map(&:to_s)
          mounts << {"name" => "cdi-mount-#{index}", "source" => mount["hostPath"].to_s, "destination" => mount["containerPath"].to_s,
                     "readonly" => options.include?("ro"), "propagation" => "None"}
        end
        edits.device_nodes.each_with_index do |node, index|
          host = (node["hostPath"] || node["path"]).to_s
          raise Error, "CDI device node #{node["path"]}: host device #{host} does not exist" unless File.exist?(host)

          # Cgroup access as CDI's container-edits: the node's permissions,
          # "rwm" when it names none; type/major/minor only when the spec
          # gives them (fillMissingInfo stats the host path otherwise).
          mount = {"name" => "cdi-device-#{index}", "source" => host, "destination" => node["path"].to_s,
                   "readonly" => false, "propagation" => "None", "device" => true,
                   "permissions" => node["permissions"].to_s.empty? ? "rwm" : node["permissions"].to_s}
          if !node["type"].to_s.empty? && Integer(node["major"] || 0) != 0
            mount.merge!("device_type" => node["type"].to_s, "major" => Integer(node["major"]), "minor" => Integer(node["minor"] || 0))
          end
          mounts << mount
        end
        definition["mounts"] = mounts
        unless edits.hooks.empty?
          begin
            Runtime::Native::Hooks.normalize(edits.hooks)
          rescue Runtime::Native::Hooks::Error => error
            raise Error, error.message
          end
          definition["cdi_hooks"] = edits.hooks
        end
        unless edits.additional_gids.empty?
          context = (definition["security_context"] ||= {})
          context["supplementalGroups"] = (Array(context["supplementalGroups"]) + edits.additional_gids).uniq
        end
        definition
      end
    end
  end
end
