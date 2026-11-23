# frozen_string_literal: true

require "base64"
require "digest/sha2"
require "json"

module Rubernetes
  module Manifest
    module ResourceReferences
      module_function

      def declared!(source, builder, kinds)
        unless source.is_a?(Hash) && source["apiVersion"] == "v1" && kinds.include?(source["kind"]) &&
               builder.result.any? { |object| object.equal?(source) }
          raise Error, "expected #{kinds.join(" or ")} declared in this manifest"
        end

        source
      end

      def resolve(source, builder, namespace, kinds: %w[ConfigMap Secret], key: nil)
        if source.is_a?(Reference)
          raise Error, "expected a reference to #{kinds.join(" or ")}" unless kinds.include?(source.kind)

          return source
        end

        declared!(source, builder, kinds)
        kind = source.fetch("kind")
        metadata = source.fetch("metadata")
        name, target_namespace = metadata.values_at("name", "namespace")
        if namespace && target_namespace && namespace != target_namespace
          raise Error, "#{kind}/#{name} is in namespace #{target_namespace.inspect}, but this workload is in #{namespace.inspect}"
        end
        if key && !source["data"].to_h.key?(key.to_s) && !(kind == "Secret" && source["stringData"].to_h.key?(key.to_s))
          raise Error, "#{kind}/#{name} has no environment key #{key.to_s.inspect}"
        end

        Reference.new(kind, name)
      end
    end

    module ConfigRollout
      ANNOTATION = "rubernetes.io/configmap-checksum"

      # A change to the selected data changes the Pod template and lets its
      # native controller perform the workload's configured update strategy.
      def rollout_on(*config_maps)
        raise Error, "rollout_on needs at least one declared ConfigMap" if config_maps.empty?

        unless @rollout_configs
          @rollout_configs = {}
          at_finish { write_config_checksum }
        end
        config_maps.each do |config|
          ResourceReferences.declared!(config, @helpers, ["ConfigMap"])
          identity = config.fetch("metadata").values_at("namespace", "name").map(&:to_s)
          data = config["data"].to_h.sort
          binary = config["binaryData"].to_h.sort.map do |key, encoded|
            begin
              raise ArgumentError unless encoded.is_a?(String)

              bytes = Base64.strict_decode64(encoded.delete("\r\n"))
            rescue ArgumentError
              raise Error, "ConfigMap/#{identity.last} binaryData key #{key.inspect} is not valid base64"
            end
            [key, Digest::SHA256.hexdigest(bytes)]
          end
          contents = [data, binary]
          if @rollout_configs.key?(identity) && @rollout_configs.fetch(identity) != contents
            raise Error, "rollout_on has conflicting declarations for ConfigMap/#{identity.last}"
          end

          @rollout_configs[identity] = contents
        end
      end

      private

      def write_config_checksum
        spec = (@workload["spec"] ||= {})
        template = (spec["template"] ||= {})
        metadata = (template["metadata"] ||= {})
        annotations = (metadata["annotations"] ||= {})
        digest = Digest::SHA256.hexdigest(JSON.generate(@rollout_configs.sort))
        if annotations.key?(ANNOTATION) && annotations[ANNOTATION] != digest
          raise Error, "rollout_on needs to set the Pod template annotation #{ANNOTATION.inspect}"
        end

        annotations[ANNOTATION] = digest
      end
    end
  end
end
