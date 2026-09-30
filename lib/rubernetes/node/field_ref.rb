# frozen_string_literal: true

require_relative "status"
require_relative "resource_manager"

module Rubernetes
  module Node
    # Resolves `fieldRef` and `resourceFieldRef` selectors the way kubelet's
    # fieldpath package does, for both environment variables and downward
    # API volume files.
    module FieldRef
      class Error < StandardError; end

      SUPPORTED_ENV_FIELDS = %w[
        metadata.name metadata.namespace metadata.uid spec.nodeName spec.serviceAccountName
        status.hostIP status.hostIPs status.podIP status.podIPs
      ].freeze
      SUPPORTED_VOLUME_FIELDS = %w[metadata.name metadata.namespace metadata.uid metadata.labels metadata.annotations].freeze
      SUPPORTED_RESOURCES = %w[limits.cpu limits.memory limits.ephemeral-storage requests.cpu requests.memory
                               requests.ephemeral-storage].freeze

      module_function

      # Downward API volume item or env valueFrom entry.
      def resolve_item(entry, pod, pod_ip: nil, host_ip: nil, node_allocatable: nil, container: nil, env: false)
        item = Helpers.string_keys(entry)
        if (field = Helpers.key(item, "fieldRef", nil))
          resolve_field(Helpers.key(field, "fieldPath").to_s, pod, pod_ip: pod_ip, host_ip: host_ip, env: env)
        elsif (resource = Helpers.key(item, "resourceFieldRef", nil))
          name = Helpers.key(resource, "containerName", nil)
          target = container || find_container(pod, name)
          raise Error, "resourceFieldRef requires a containerName" if target.nil?

          resolve_resource(Helpers.key(resource, "resource").to_s, target, divisor: Helpers.key(resource, "divisor", "1"),
                                                                           node_allocatable: node_allocatable)
        else
          raise Error, "item must carry fieldRef or resourceFieldRef"
        end
      end

      def resolve_field(field_path, pod, pod_ip: nil, host_ip: nil, env: false)
        metadata = Helpers.key(pod, "metadata", {})
        spec = Helpers.key(pod, "spec", {})
        status = Helpers.key(pod, "status", {})
        path, subscript = split_subscript(field_path)
        if subscript
          case path
          when "metadata.labels" then return Helpers.key(Helpers.key(metadata, "labels", {}) || {}, subscript, "").to_s
          when "metadata.annotations" then return Helpers.key(Helpers.key(metadata, "annotations", {}) || {}, subscript, "").to_s
          else raise Error, "unsupported subscript field #{field_path.inspect}"
          end
        end

        case path
        when "metadata.name" then Helpers.key(metadata, "name", "").to_s
        when "metadata.namespace" then Helpers.key(metadata, "namespace", "").to_s
        when "metadata.uid" then Helpers.key(metadata, "uid", "").to_s
        when "metadata.labels"
          raise Error, "metadata.labels is not a valid env field" if env

          format_map(Helpers.key(metadata, "labels", {}) || {})
        when "metadata.annotations"
          raise Error, "metadata.annotations is not a valid env field" if env

          format_map(Helpers.key(metadata, "annotations", {}) || {})
        when "spec.nodeName" then Helpers.key(spec, "nodeName", "").to_s
        when "spec.serviceAccountName" then Helpers.key(spec, "serviceAccountName", Helpers.key(spec, "serviceAccount", "default")).to_s
        when "status.hostIP" then (host_ip || Helpers.key(status, "hostIP", "")).to_s
        when "status.hostIPs" then Array(host_ip ? [host_ip] : Helpers.key(status, "hostIPs", []).map do |entry|
          Helpers.key(entry, "ip", entry)
        end).join(",")
        when "status.podIP" then (pod_ip.is_a?(Array) ? pod_ip.first : pod_ip || Helpers.key(status, "podIP", "")).to_s
        when "status.podIPs"
          ips = if pod_ip.is_a?(Array)
                  pod_ip
                else
                  (if pod_ip
                     [pod_ip]
                   else
                     Helpers.key(status, "podIPs", []).map do |entry|
                       Helpers.key(entry, "ip", entry)
                     end
                   end)
                end
          ips.map(&:to_s).join(",")
        else
          raise Error, "unsupported fieldPath #{field_path.inspect}"
        end
      end

      # kubelet: the value is ceil(quantity / divisor) rendered as an integer;
      # an unset limit falls back to the node allocatable (the container can
      # use the whole node), an unset request is zero.
      def resolve_resource(resource, container, divisor: "1", node_allocatable: nil)
        raise Error, "unsupported resource #{resource.inspect}" unless SUPPORTED_RESOURCES.include?(resource)

        kind, name = resource.split(".", 2)
        resources = Helpers.key(container, "resources", {}) || {}
        section = Helpers.key(resources, kind, {}) || {}
        value = Helpers.key(section, name, nil)
        if value.nil? && kind == "limits"
          value = Helpers.key(node_allocatable || {}, name, nil)
          value = Helpers.key(Helpers.key(resources, "requests", {}) || {}, name, nil) if value.nil?
        end
        return "0" if value.nil?

        quantity = parse_quantity(value, name)
        divisor_value = parse_quantity(divisor.to_s.empty? ? "1" : divisor, name)
        # An unset Quantity serialises as "0"; kubelet (fieldpath
        # ExtractContainerResourceValue) treats a zero divisor as 1.
        divisor_value = parse_quantity("1", name) if divisor_value.zero?
        raise Error, "divisor must be positive" unless divisor_value.positive?

        (quantity / divisor_value).ceil.to_s
      end

      def parse_quantity(value, resource)
        ResourceManager.new.parse_quantity(value, resource == "cpu" ? "cpu" : "memory")
      rescue StandardError => error
        raise Error, "invalid quantity #{value.inspect}: #{error.message}"
      end

      def find_container(pod, name)
        spec = Helpers.key(pod, "spec", {})
        (Array(Helpers.key(spec, "containers", [])) + Array(Helpers.key(spec, "initContainers", []))).find do |container|
          Helpers.key(container, "name", "").to_s == name.to_s
        end
      end

      def split_subscript(field_path)
        match = field_path.to_s.match(/\A([a-zA-Z.]+)\['([^']*)'\]\z/)
        return [field_path.to_s, nil] unless match

        [match[1], match[2]]
      end

      # Go's fieldpath.FormatMap: `key="value"` per line with %q quoting,
      # sorted by key.
      def format_map(map)
        map.to_h.map { |key, value| [key.to_s, value.to_s] }.sort.map { |key, value| "#{key}=#{go_quote(value)}" }.join("\n")
      end

      def go_quote(value)
        escaped = value.each_char.map do |char|
          case char
          when "\"" then "\\\""
          when "\\" then "\\\\"
          when "\n" then "\\n"
          when "\r" then "\\r"
          when "\t" then "\\t"
          else
            char.ord < 0x20 || char.ord == 0x7f ? format("\\x%02x", char.ord) : char
          end
        end.join
        "\"#{escaped}\""
      end
    end
  end
end
