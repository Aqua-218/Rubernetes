# frozen_string_literal: true

require_relative "hpa_conversion"

module Rubernetes
  module API
    # One stored object per built-in resource, whatever version it is served
    # in.  kube-apiserver stores a resource once (the key names no version)
    # and converts through the internal type on the way in and out; serving
    # each version from its own storage meant an HPA created through
    # autoscaling/v2 was not there for autoscaling/v1, and a DRA driver
    # speaking resource.k8s.io/v1beta1 saw none of the v1 ResourceSlices.
    #
    # The storage key here names a version (the registry's layout), so it is
    # a version that is served by default when there is one -- existing
    # objects stay where they are -- and upstream's storage version
    # otherwise.  Objects are held in that version's shape and converted on
    # read to the version asked for.
    #
    # Shapes differ only for autoscaling (v1 <-> v2, HPAConversion) and
    # resource.k8s.io/v1beta1 (ResourceV1beta1); every other multi-version
    # resource has identical schemas across its versions (checked against the
    # pinned OpenAPI corpus), so converting it is relabelling apiVersion.
    module BuiltinConversion
      # pkg/kubeapiserver/default_storage_factory_builder.go overrides; any
      # other resource stores in its group's preferred version.
      UPSTREAM_STORAGE_VERSIONS = {
        %w[coordination.k8s.io leasecandidates] => "v1beta1",
        %w[admissionregistration.k8s.io mutatingadmissionpolicies] => "v1beta1",
        %w[admissionregistration.k8s.io mutatingadmissionpolicybindings] => "v1beta1",
        %w[certificates.k8s.io clustertrustbundles] => "v1beta1",
        %w[certificates.k8s.io podcertificaterequests] => "v1beta1",
        %w[storagemigration.k8s.io storagemigrations] => "v1beta1",
        %w[resource.k8s.io devicetaintrules] => "v1alpha3",
        %w[resource.k8s.io resourcepoolstatusrequests] => "v1alpha3",
        %w[scheduling.k8s.io workloads] => "v1alpha2",
        %w[scheduling.k8s.io podgroups] => "v1alpha2"
      }.freeze

      class ConversionError < StandardError; end

      module_function

      # Kubernetes version priority: GA before beta before alpha, higher
      # numbers first.
      def version_rank(version)
        match = /\Av(\d+)(?:(alpha|beta)(\d+))?\z/.match(version.to_s)
        return [3, 0, 0] unless match

        stage = {nil => 0, "beta" => 1, "alpha" => 2}.fetch(match[2])
        [stage, -match[1].to_i, -match[3].to_i]
      end

      def upstream_storage_version(group, resource, versions)
        UPSTREAM_STORAGE_VERSIONS[[group.to_s, resource.to_s]] || versions.min_by { |version| version_rank(version) }
      end

      # The version whose storage key the resource lives under.
      def storage_version(group, resource, versions, default_served: nil)
        upstream = upstream_storage_version(group, resource, versions)
        served = default_served ? versions.select { |version| default_served.call(version) } : []
        return upstream if served.empty? || served.include?(upstream)

        served.min_by { |version| version_rank(version) }
      end

      # The CRD converter interface (convert(objects, to_version:)) for a
      # built-in resource.
      class Converter
        attr_reader :group, :resource

        def initialize(group:, resource:)
          @group = group.to_s
          @resource = resource.to_s
        end

        def convert(objects, to_version:)
          objects.map { |object| convert_one(object, to_version.to_s) }
        end

        def convert_one(object, to_version)
          return object unless object.is_a?(Hash)

          from = object["apiVersion"].to_s.split("/", 2).last
          return object if from == to_version

          target = @group.empty? ? to_version : "#{@group}/#{to_version}"
          case @group
          when "autoscaling"
            HPAConversion.convert(object, to_version: target)
          when "resource.k8s.io"
            ResourceV1beta1.convert(object, from: from, to: to_version).merge("apiVersion" => target)
          else
            object.merge("apiVersion" => target)
          end
        rescue ConversionError
          raise
        rescue StandardError => error
          raise ConversionError, "#{@group}/#{@resource}: #{error.message}"
        end
      end

      # pkg/apis/resource/v1beta1/conversion.go: v1beta1 nests a Device's
      # fields under `basic` and flattens a DeviceRequest's `exactly`;
      # ResourceSliceSpec nodeName/allNodes are values rather than pointers.
      # v1beta2 and v1 share one shape.
      module ResourceV1beta1
        MAIN_REQUEST_FIELDS = %w[deviceClassName selectors allocationMode count adminAccess tolerations capacity].freeze
        BASIC_FIELDS = %w[attributes capacity consumesCounters nodeName nodeSelector allNodes taints bindsToNode bindingConditions
                          bindingFailureConditions allowMultipleAllocations nodeAllocatableResourceMappings].freeze

        module_function

        def convert(object, from:, to:)
          object = deep_copy(object)
          if from == "v1beta1" && to != "v1beta1"
            walk(object, :up)
          elsif to == "v1beta1" && from != "v1beta1"
            walk(object, :down)
          else
            object
          end
        end

        def walk(object, direction)
          case object["kind"]
          when "ResourceClaim"
            convert_requests(object.dig("spec", "devices"), direction)
          when "ResourceClaimTemplate"
            convert_requests(object.dig("spec", "spec", "devices"), direction)
          when "ResourceSlice"
            spec = object["spec"]
            if spec.is_a?(Hash)
              # "" and false are the value types' zero values: absent on the
              # wire in v1beta1, nil pointers in v1.
              spec.delete("nodeName") if spec.key?("nodeName") && spec["nodeName"].to_s.empty?
              spec.delete("allNodes") if spec.key?("allNodes") && spec["allNodes"] != true
              if spec.key?("devices")
                spec["devices"] = Array(spec["devices"]).map do |device|
                  direction == :up ? device_up(device) : device_down(device)
                end
              end
            end
          end
          object
        end

        def convert_requests(devices, direction)
          return unless devices.is_a?(Hash) && devices["requests"].is_a?(Array)

          devices["requests"] = devices["requests"].map { |request| direction == :up ? request_up(request) : request_down(request) }
        end

        # hasAnyMainRequestFieldsSet: a present selectors or tolerations list
        # counts, a zero count or an empty class name does not.
        def request_up(request)
          return request unless request.is_a?(Hash)

          main = MAIN_REQUEST_FIELDS.select { |field| request.key?(field) }
          set = !request["deviceClassName"].to_s.empty? || !request["selectors"].nil? || !request["allocationMode"].to_s.empty? ||
                request["count"].to_i != 0 || !request["adminAccess"].nil? || !request["tolerations"].nil? || !request["capacity"].nil?
          out = request.reject { |key, _| main.include?(key) }
          if set
            exactly = {}
            exactly["deviceClassName"] = request["deviceClassName"].to_s
            exactly["selectors"] = request["selectors"] unless request["selectors"].nil? || Array(request["selectors"]).empty?
            exactly["allocationMode"] = request["allocationMode"] unless request["allocationMode"].to_s.empty?
            exactly["count"] = request["count"] if request["count"].to_i != 0
            exactly["adminAccess"] = request["adminAccess"] unless request["adminAccess"].nil?
            exactly["tolerations"] = request["tolerations"] unless Array(request["tolerations"]).empty?
            exactly["capacity"] = request["capacity"] unless request["capacity"].nil?
            # SetDefaults_ExactDeviceRequest, which every v1/v1beta2 read of it
            # applies.
            exactly["allocationMode"] = "ExactCount" if exactly["allocationMode"].to_s.empty?
            exactly["count"] = 1 if exactly["allocationMode"] == "ExactCount" && exactly["count"].to_i.zero?
            out["exactly"] = exactly
          end
          out
        end

        def request_down(request)
          return request unless request.is_a?(Hash)

          out = request.reject { |key, _| key == "exactly" }
          exactly = request["exactly"]
          # v1beta1 deviceClassName is required: present, if empty.
          out["deviceClassName"] = exactly.is_a?(Hash) ? exactly["deviceClassName"].to_s : ""
          if exactly.is_a?(Hash)
            out["selectors"] = exactly["selectors"] unless Array(exactly["selectors"]).empty?
            out["allocationMode"] = exactly["allocationMode"] unless exactly["allocationMode"].to_s.empty?
            out["count"] = exactly["count"] if exactly["count"].to_i != 0
            out["adminAccess"] = exactly["adminAccess"] unless exactly["adminAccess"].nil?
            out["tolerations"] = exactly["tolerations"] unless Array(exactly["tolerations"]).empty?
            out["capacity"] = exactly["capacity"] unless exactly["capacity"].nil?
          end
          out
        end

        def device_up(device)
          return device unless device.is_a?(Hash)

          out = device.reject { |key, _| key == "basic" }
          basic = device["basic"]
          if basic.is_a?(Hash)
            BASIC_FIELDS.each do |field|
              value = basic[field]
              next if omitted?(value)

              out[field] = value
            end
          end
          out
        end

        def device_down(device)
          return device unless device.is_a?(Hash)

          out = device.reject { |key, _| BASIC_FIELDS.include?(key) }
          basic = {}
          BASIC_FIELDS.each do |field|
            value = device[field]
            next if omitted?(value)

            basic[field] = value
          end
          out["basic"] = basic
          out
        end

        # Pointers keep false and ""; omitempty drops nil and empty lists or maps.
        def omitted?(value) = value.nil? || ((value.is_a?(Array) || value.is_a?(Hash)) && value.empty?)

        def deep_copy(value)
          case value
          when Hash then value.to_h { |key, item| [key, deep_copy(item)] }
          when Array then value.map { |item| deep_copy(item) }
          else value
          end
        end
      end
    end
  end
end
