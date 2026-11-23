# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # Publish the encoding of each stored built-in resource after the
      # apiserver identity Lease exists. Requests that could write an
      # unregistered encoding wait for that resource's report to succeed.
      module StorageVersions
        STORAGE_VERSION_GROUP = "internal.apiserver.k8s.io"
        STORAGE_VERSION_API = "#{STORAGE_VERSION_GROUP}/v1alpha1".freeze
        STORAGE_VERSION_GATE = "StorageVersionAPI"

        def storage_version_reporting?
          feature_gate_enabled?(STORAGE_VERSION_GATE) && feature_gate_enabled?("APIServerIdentity")
        end

        def storage_version_registered?
          @storage_version_mutex.nil? || @storage_version_mutex.synchronize { @storage_version_pending.empty? }
        end

        def publish_storage_versions!(server_id)
          return true unless storage_version_reporting?

          target = @registry.find_gvr(group: STORAGE_VERSION_GROUP, version: "v1alpha1", resource: "storageversions")
          return false unless target && resource_enabled?(target)

          succeeded = true
          storage_version_reports.each do |name, report|
            publish_storage_version(target, name, report, server_id)
            update_storage_version_barrier(report, nil)
          rescue MemoryStore::Error, Status::Error => error
            succeeded = false
            update_storage_version_barrier(report, error)
          end
          succeeded
        end

        private

        def initialize_storage_version_barrier
          return unless storage_version_reporting?

          @storage_version_mutex = Mutex.new
          @storage_version_pending = storage_version_reports.values.flat_map { |report| report.fetch(:resources) }.to_h { |key| [key, nil] }
        end

        def storage_version_reports
          @storage_version_reports ||= begin
            resources = @registry.resources.reject(&:custom?)
            by_storage = resources.group_by(&:storage_gvr)
            enabled_resources.select { |resource| persisted_for_storage_version?(resource) }.group_by(&:storage_gvr).to_h do |storage, versions|
              canonical = versions.min_by { |resource| [resource.group, resource.resource] }
              group = canonical.group.empty? ? "core" : canonical.group
              served = versions.select { |resource| resource.group == canonical.group && resource.resource == canonical.resource }
              ["#{group}.#{canonical.resource}",
               {encoding: canonical.storage_encoding_gvr.group_version,
                decoded: by_storage.fetch(storage).map(&:api_version).uniq,
                served: served.map(&:api_version).uniq, resources: versions.map { |resource| [resource.group, resource.resource] }.uniq}]
            end
          end
        end

        def persisted_for_storage_version?(resource)
          !resource.custom? && resource.verbs.include?("get") &&
            resource.verbs.any? { |verb| %w[create update patch delete].include?(verb) }
        end

        def storage_version_precondition!(request, route)
          return unless @storage_version_mutex && route.resource_route? && resource_enabled?(route.resource)
          return if %w[GET HEAD OPTIONS].include?(request.method)

          resource = route.resource
          group = resource.group
          name = resource.resource
          return if group == STORAGE_VERSION_GROUP && name == "storageversions"
          return if group == "coordination.k8s.io" && name == "leases" && route.namespace == "kube-system"
          return if storage_version_namespace_bootstrap?(request, group, name)

          key = [group, name]
          pending, error = @storage_version_mutex.synchronize { [@storage_version_pending.key?(key), @storage_version_pending[key]] }
          return unless pending

          qualified = group.empty? ? name : "#{name}.#{group}"
          raise Status::Error.new(message: "wait for storage version registration to complete for resource: #{qualified}, " \
                                           "last seen error: #{error ? error.message : "<nil>"}",
                                  code: 503, reason: "ServiceUnavailable")
        end

        def storage_version_resource?(resource)
          resource.group == STORAGE_VERSION_GROUP && resource.resource == "storageversions"
        end

        def storage_version_validation(object)
          name = object.dig("metadata", "name").to_s
          group, separator, resource = name.rpartition(".")
          causes = []
          if separator.empty?
            causes << ObjectValidation.invalid("metadata.name", name, "name must be in the form of <group>.<resource>")
          elsif !valid_storage_version_dns?(group) || !ObjectValidation::DNS1035_LABEL.match?(resource) || resource.length > 63
            causes << ObjectValidation.invalid("metadata.name", name, "must have a DNS subdomain group and a DNS-1035 resource label")
          end
          status = object["status"]
          return causes unless status.is_a?(Hash)

          entries = Array(status["storageVersions"]).grep(Hash)
          seen = Set.new
          entries.each_with_index do |entry, index|
            path = "status.storageVersions[#{index}]"
            id = entry["apiServerID"].to_s
            causes << ObjectValidation.invalid("#{path}.apiServerID", id, "must be a DNS subdomain") unless valid_storage_version_dns?(id)
            causes << ObjectValidation.invalid("#{path}.apiServerID", id, "duplicate API server ID") unless seen.add?(id)
            causes.concat(storage_version_entry_validation(entry, path))
          end
          encodings = entries.map { |entry| entry["encodingVersion"] }.uniq
          expected = encodings.first if encodings.length == 1
          common = status["commonEncodingVersion"]
          if common != expected
            causes << ObjectValidation.invalid("status.commonEncodingVersion", common, "must match the encoding version agreed by all servers")
          end
          causes.concat(storage_version_condition_validation(status["conditions"]))
        end

        def storage_version_entry_validation(entry, path)
          encoding = entry["encodingVersion"].to_s
          decoded = Array(entry["decodableVersions"])
          served = Array(entry["servedVersions"])
          causes = []
          unless valid_storage_version_api_version?(encoding)
            causes << ObjectValidation.invalid("#{path}.encodingVersion", encoding, "must be a valid API version")
          end
          each = {"decodableVersions" => decoded, "servedVersions" => served}
          each.each do |field, values|
            values.each_with_index do |value, index|
              next if valid_storage_version_api_version?(value.to_s)

              causes << ObjectValidation.invalid("#{path}.#{field}[#{index}]", value, "must be a valid API version")
            end
          end
          causes << ObjectValidation.invalid("#{path}.decodableVersions", decoded, "must include encodingVersion #{encoding}") unless decoded.include?(encoding)
          served.each_with_index do |version, index|
            next if decoded.include?(version)

            causes << ObjectValidation.invalid("#{path}.servedVersions[#{index}]", version, "must be included in decodableVersions")
          end
          causes
        end

        def storage_version_condition_validation(conditions)
          seen = Set.new
          Array(conditions).each_with_index.with_object([]) do |(condition, index), causes|
            next unless condition.is_a?(Hash)

            path = "status.conditions[#{index}]"
            type = condition["type"].to_s
            causes << ObjectValidation.invalid("#{path}.type", type, "condition type must be unique") unless seen.add?(type)
            %w[type status].each do |field|
              value = condition[field].to_s
              ObjectValidation.qualified_name_errors(value).each do |message|
                causes << ObjectValidation.invalid("#{path}.#{field}", value, message)
              end
            end
            %w[reason message].each do |field|
              causes << ObjectValidation.required("#{path}.#{field}") if condition[field].to_s.empty?
            end
          end
        end

        def valid_storage_version_dns?(value)
          value.length <= 253 && ObjectValidation::DNS1123_SUBDOMAIN.match?(value)
        end

        def valid_storage_version_api_version?(value)
          parts = value.split("/", -1)
          version = parts.pop.to_s
          return false if version.length > 63 || !ObjectValidation::DNS1035_LABEL.match?(version)

          parts.empty? || (parts.length == 1 && valid_storage_version_dns?(parts.first))
        end

        def storage_version_namespace_bootstrap?(request, group, resource)
          return false unless group.empty? && resource == "namespaces" && request.method == "POST"

          identity = user_info(request.attributes&.user || request_identity(request))
          identity["username"] == "system:apiserver" && Array(identity["groups"]).include?("system:masters")
        end

        def update_storage_version_barrier(report, error)
          @storage_version_mutex.synchronize do
            report.fetch(:resources).each do |key|
              if error.nil?
                @storage_version_pending.delete(key)
              elsif @storage_version_pending.key?(key)
                @storage_version_pending[key] = error
              end
            end
          end
        end

        def publish_storage_version(resource, name, report, server_id)
          key = {resource: resource, namespace: :cluster}
          version = find_or_create_storage_version(key, name)
          current = version["status"] || {}
          desired = reported_storage_status(current, version, report, server_id)
          return if current == desired

          @store.update(**key, name: name, object: version.merge("status" => desired),
                               resource_version: version.dig("metadata", "resourceVersion"))
        end

        def find_or_create_storage_version(key, name)
          @store.get(**key, name: name)
        rescue MemoryStore::NotFound
          object = {"apiVersion" => STORAGE_VERSION_API, "kind" => "StorageVersion", "metadata" => {"name" => name}, "spec" => {}, "status" => {}}
          @store.create(**key, object: prepare_created_metadata(object, resource: key.fetch(:resource)))
        end

        def reported_storage_status(current, version, report, server_id)
          entries = Array(current["storageVersions"]).reject { |entry| entry["apiServerID"] == server_id }
          entries << {"apiServerID" => server_id, "encodingVersion" => report.fetch(:encoding),
                      "decodableVersions" => report.fetch(:decoded), "servedVersions" => report.fetch(:served)}
          entries.sort_by! { |entry| entry.fetch("apiServerID") }
          encodings = entries.map { |entry| entry.fetch("encodingVersion") }.uniq
          common = encodings.first if encodings.length == 1
          others, equal = Array(current["conditions"]).partition { |condition| condition["type"] != "AllEncodingVersionsEqual" }
          previous = equal.first || {}
          status = common ? "True" : "False"
          timestamp = previous["lastTransitionTime"] if status == previous["status"] && common == current["commonEncodingVersion"]
          condition = {"type" => "AllEncodingVersionsEqual", "status" => status, "lastTransitionTime" => timestamp || @clock.call.utc.iso8601,
                       "reason" => common ? "CommonEncodingVersionSet" : "CommonEncodingVersionUnset",
                       "message" => common ? "Common encoding version set" : "Common encoding version unset"}
          generation = version.dig("metadata", "generation")
          condition["observedGeneration"] = generation if generation
          {"storageVersions" => entries, "commonEncodingVersion" => common, "conditions" => [*others, condition]}.compact
        end
      end
    end
  end
end
