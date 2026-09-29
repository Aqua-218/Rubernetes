# frozen_string_literal: true

require "json"
require_relative "managed_fields"

module Rubernetes
  module API
    # The field manager each REST handler installs (apiserver
    # handlers.RequestScope.FieldManager): a kind's type converter built from
    # the OpenAPI v3 document that serves it, the strategy's reset fields for
    # the subresource, and the kind's version converter.
    class FieldManagerRegistry
      MF = ManagedFields
      PE = MF::FieldPath::PathElement

      # Status strategies that reset metadata as well as spec
      # (GetResetFields in pkg/registry/**, kube-aggregator and
      # apiextensions-apiserver, v1.36.2).
      STATUS_METADATA_RESET_KINDS = %w[
        ValidatingAdmissionPolicy StorageVersion FlowSchema PriorityLevelConfiguration ServiceCIDR DeviceTaintRule
        ResourceClaim ResourcePoolStatusRequest PodGroup StorageVersionMigration VolumeAttachment APIService
      ].freeze
      STATUS_RESET = {
        "Deployment" => [%w[spec], %w[metadata labels]],
        "Pod" => [%w[spec], %w[metadata deletionTimestamp], %w[metadata ownerReferences]],
        "CertificateSigningRequest" => [%w[spec], %w[status conditions]]
      }.freeze
      MAIN_RESET = {"CertificateSigningRequest" => [%w[spec], %w[status]]}.freeze
      # Main strategies without GetResetFields although the kind has status.
      MAIN_WITHOUT_RESET = %w[PodCertificateRequest].freeze
      SUBRESOURCE_RESET = {%w[CertificateSigningRequest approval] => [%w[spec], %w[status certificate]]}.freeze

      # Built-in workloads whose Scale maps to .spec.replicas
      # (registry/*/storage ScaleREST replicasPathIn*).
      SCALE_REPLICAS = [PE.field("spec"), PE.field("replicas")].freeze

      def initialize(openapi:, clock: -> { Time.now.utc })
        @openapi = openapi
        @clock = clock
        @converters = {}
        @managers = {}
        @mutex = Mutex.new
      end

      # The field manager for +resource+ (and +subresource+), or nil when
      # the kind is served without one.
      def field_manager(resource, subresource = nil)
        converter = type_converter(resource.group, resource.version)
        key = [resource.group, resource.version, resource.kind, subresource.to_s, converter.object_id, resource.object_id]
        @mutex.synchronize do
          @managers.clear if @managers.length > 512
          @managers[key] ||= MF::FieldManager.new(
            type_converter: converter, group: resource.group, version: resource.version, kind: resource.kind,
            subresource: subresource, reset_fields: reset_fields(resource, subresource),
            new_object: subresource.to_s.empty? ? zero_object(resource.group, resource.version, resource.kind) : nil,
            object_converter: object_converter(resource), version_types: method(:strict_type_for), clock: @clock
          )
        end
      end

      ZERO_OBJECTS = File.expand_path("../../../schema/kubernetes/v1.36.2-defaults/zero_objects.json", __dir__)

      # Creater.New(kind): the live object a create's update is compared
      # against -- the kind's Go zero value, in which every struct field that
      # is not a pointer is already present (tools/schema/import_zero_objects.rb).
      # A custom resource starts from nothing.
      def self.zero_objects
        @zero_objects ||= begin
          objects = JSON.parse(File.read(ZERO_OBJECTS)).fetch("objects")
          objects.transform_values { |object| deep_freeze(object) }.freeze
        rescue Errno::ENOENT, JSON::ParserError
          {}.freeze
        end
      end

      def self.deep_freeze(value)
        case value
        when Hash then value.each_value { |item| deep_freeze(item) }
        when Array then value.each { |item| deep_freeze(item) }
        end
        value.freeze
      end

      def zero_object(group, version, kind)
        self.class.zero_objects["#{group}/#{version}/#{kind}"]
      end

      # The autoscaling/v1 Scale field manager of a scale subresource.
      def scale_field_manager
        converter = type_converter("autoscaling", "v1")
        key = [:scale, converter.object_id]
        @mutex.synchronize do
          @managers[key] ||= MF::FieldManager.new(type_converter: converter, group: "autoscaling", version: "v1",
                                                   kind: "Scale", subresource: "scale", clock: @clock)
        end
      end

      # ResourcePathMappings for a scaled kind: every version of the parent
      # keeps replicas at .spec.replicas (a CustomResourceDefinition names its
      # own specReplicasPath).
      def scale_mappings(resource, replicas_path: nil)
        path = replicas_path ? replicas_path.map { |part| PE.field(part) } : SCALE_REPLICAS
        Hash.new(path).merge(resource.api_version => path)
      end

      # The type converter of a group/version: its OpenAPI v3 document's
      # components, rebuilt whenever the document is republished; the deduced
      # converter when the document does not declare the kind.
      def type_converter(group, version)
        path = group.to_s.empty? ? "/openapi/v3/api/#{version}" : "/openapi/v3/apis/#{group}/#{version}"
        document = @openapi.document_for(path)
        schemas = document.is_a?(Hash) ? document.dig("components", "schemas") : nil
        return MF::Schema::DeducedTypeConverter.new unless schemas.is_a?(Hash)

        @mutex.synchronize do
          cached = @converters[path]
          return cached.last if cached && cached.first.equal?(document)
        end
        built = Fallback.new(MF::Schema::TypeConverter.from_components(schemas))
        @mutex.synchronize { @converters[path] = [document, built] }
        built
      end

      # The kind in another served version, nil when that version does not
      # declare it (the manager's entry is then dropped, IsMissingVersionError).
      def strict_type_for(group, version, kind)
        converter = type_converter(group, version)
        converter.respond_to?(:strict_type_for) ? converter.strict_type_for(group, version, kind) : nil
      end

      def reset_fields(resource, subresource)
        paths = reset_paths(resource, subresource.to_s)
        return nil if paths.nil? || paths.empty?

        MF::FieldPath::Set.from_paths(paths.map { |path| path.map { |part| PE.field(part) } })
      end

      private

      def reset_paths(resource, subresource)
        kind = resource.kind.to_s
        has_status = resource.respond_to?(:subresource) && resource.subresource("status")
        case subresource
        when ""
          return MAIN_RESET[kind] if MAIN_RESET.key?(kind)
          return nil if MAIN_WITHOUT_RESET.include?(kind) || !has_status

          [%w[status]]
        when "status"
          return STATUS_RESET[kind] if STATUS_RESET.key?(kind)
          if STATUS_METADATA_RESET_KINDS.include?(kind) || (resource.respond_to?(:custom?) && resource.custom?)
            return [%w[metadata], %w[spec]]
          end

          [%w[spec]]
        else
          SUBRESOURCE_RESET[[kind, subresource]]
        end
      end

      def object_converter(resource)
        converter = resource.respond_to?(:converter) ? resource.converter : nil
        return nil if converter.nil?

        lambda do |object, from, to|
          source = object.is_a?(Hash) ? object.merge("apiVersion" => from) : object
          converter.convert([source], to_version: to.to_s.split("/").last).first
        end
      end

      # A kind the document does not declare is handled as deduced
      # (NewDeducedTypeConverter), as for a CustomResourceDefinition whose
      # schema cannot be converted.
      class Fallback
        def initialize(converter)
          @converter = converter
          @deduced = MF::Schema::DeducedTypeConverter.new
        end

        def type_for(group, version, kind)
          @converter.type_for(group, version, kind) || @deduced.type_for(group, version, kind)
        end

        def strict_type_for(group, version, kind) = @converter.type_for(group, version, kind)
        def errors = @converter.errors
      end
    end
  end
end
