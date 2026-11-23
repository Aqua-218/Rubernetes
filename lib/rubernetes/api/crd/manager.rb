# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "net/http"
require "openssl"
require "securerandom"
require "time"
require "uri"

require_relative "structural_schema"
require_relative "openapi_metadata"
require_relative "openapi_routes"
require_relative "../registry"

module Rubernetes
  module API
    module CRD
      # Serves CustomResourceDefinitions (apiextensions.k8s.io/v1): for each
      # served version an API::Resource is registered with a structural-schema
      # contract (defaulting, pruning, validation, CEL rules), status/scale
      # subresources, printer columns and selectable fields; discovery and
      # OpenAPI v3 are published; NamesAccepted / Established conditions are
      # written to the CRD status; conversion between versions uses the
      # None strategy (apiVersion rewrite) or a conversion webhook; deleting a
      # CRD removes its resources after the custom resources are cleaned up.
      class Manager
        GROUP = "apiextensions.k8s.io"
        RESOURCE = "customresourcedefinitions"
        CLEANUP_FINALIZER = "customresourcecleanup.apiextensions.k8s.io"
        MAX_CONVERSION_BYTES = 3 * 1024 * 1024

        class ConversionError < StandardError; end

        Served = Struct.new(:crd_name, :group, :versions, :storage_version, :names, :digest, :deprecations, :terminating, keyword_init: true)

        attr_reader :served

        def initialize(registry:, store:, openapi:, cel: nil, webhook_client: nil, clock: -> { Time.now.utc }, logger: nil)
          @registry = registry
          @store = store
          @openapi = openapi
          @cel = cel
          @webhook_client = webhook_client
          @clock = clock
          @logger = logger
          @served = {}
          @mutex = Monitor.new
        end

        # Register every established CRD already in the store.
        def bootstrap!(crds)
          crds.each { |crd| sync(crd) }
        end

        # Reconcile one CRD object; returns the status conditions written.
        def sync(crd)
          name = crd.dig("metadata", "name")
          spec = crd["spec"] || {}
          @mutex.synchronize do
            terminating = Array(crd.dig("status", "conditions")).any? { |condition| condition.values_at("type", "status") == %w[Terminating True] }
            # Every apiserver re-syncs a CRD each time the object changes,
            # status writes included.  Withdrawing and re-registering an
            # unchanged definition left a window in which its resources
            # answered 404, so an unchanged spec keeps what is served.
            digest = JSON.generate(spec)
            if @served[name]&.digest == digest
              @served[name].terminating = terminating
              touch_regeneration("apiextensions_openapi_v2_regeneration_count", {"crd" => name, "reason" => "update"})
              return conditions(crd, accepted: true, established: true)
            end

            conflict = names_conflict(crd)
            return conditions(crd, accepted: false, reason: "NameConflict", message: conflict) if conflict

            served_versions = Array(spec["versions"]).select { |version| version["served"] == true }
            regenerations = openapi_before(name, spec["group"], served_versions)
            previous = @served[name]
            previously_served = !previous.nil?
            withdraw_serving(name)
            storage_version = Array(spec["versions"]).find { |version| version["storage"] == true }&.fetch("name")
            names = spec["names"] || {}
            registered = []
            begin
              served_versions.each do |version|
                register_version(crd, version, storage_version)
                registered << version["name"]
              end
              record_openapi_published(name, spec["group"], previously_served, regenerations)
            rescue StructuralSchema::NotStructural => error
              # No longer established: a spec it had is removed, and so is
              # every version this attempt registered before the one that
              # failed (@served is not set yet, so withdraw alone missed
              # them and left them served).
              record_openapi_removed(previous) if previous
              registered.each do |version|
                @registry.unregister(group: spec["group"], version: version, resource: names["plural"])
                @openapi.withdraw(group: spec["group"], version: version, owner: name)
              end
              withdraw(name)
              return conditions(crd, accepted: true, established: false, reason: "NonStructuralSchema", message: error.message)
            end
            # crdHandler: a deprecated version's requests carry its
            # deprecationWarning, or "<group>/<version> <Kind> is deprecated".
            deprecations = served_versions.select { |version| version["deprecated"] == true }.to_h do |version|
              warning = version["deprecationWarning"]
              [version["name"], warning.nil? ? "#{spec["group"]}/#{version["name"]} #{names["kind"]} is deprecated" : warning.to_s]
            end
            @served[name] = Served.new(crd_name: name, group: spec["group"], versions: served_versions.map { |version| version["name"] },
                                       storage_version: storage_version, names: names, digest: digest, deprecations: deprecations, terminating: terminating)
            conditions(crd, accepted: true, established: true)
          end
        end

        # The warning a request to a deprecated served version gets, or nil.
        def deprecation_warning(group, version, plural)
          entry = @mutex.synchronize do
            @served.values.find { |candidate| candidate.group == group.to_s && candidate.names["plural"] == plural.to_s }
          end
          entry&.deprecations&.fetch(version.to_s, nil)
        end

        # A terminating definition stays served so controllers can remove
        # finalizers from existing instances.
        def terminating?(name)
          @mutex.synchronize { @served[name]&.terminating == true }
        end

        # Remove discovery and OpenAPI after the definition disappears.
        def withdraw(name)
          @mutex.synchronize do
            entry = @served[name]
            record_openapi_removed(entry) if entry
            withdraw_serving(name)
          end
        end

        def withdraw_serving(name)
          @mutex.synchronize do
            entry = @served.delete(name)
            return unless entry

            entry.versions.each do |version|
              @registry.unregister(group: entry.group, version: version, resource: entry.names["plural"])
              @openapi.withdraw(group: entry.group, version: version, owner: name)
            end
          end
        end

        # CRD names currently served, for a reconciler that must withdraw the
        # ones deleted through another apiserver.
        def served_names
          @mutex.synchronize { @served.keys }
        end

        def serving?(group, version, resource)
          @mutex.synchronize do
            @served.values.any? do |entry|
              entry.group == group && entry.versions.include?(version) && entry.names["plural"] == resource
            end
          end
        end

        # Delete every custom resource of the CRD (finalizer handling).
        def cleanup_resources(crd, &)
          spec = crd["spec"] || {}
          storage_version = Array(spec["versions"]).find { |version| version["storage"] == true }&.fetch("name")
          return 0 if storage_version.nil?

          gvr = GVR.new(group: spec["group"], version: Resource::CUSTOM_STORAGE_VERSION,
                        resource: spec.dig("names", "plural"))
          count = 0
          @store.list("registry/#{gvr}/").items.each do |object|
            yield(object)
            count += 1
          end
          count
        end

        private

        # apiextensions-apiserver's openapi (v2) and openapiv3 controllers
        # create a regeneration counter series -- regenerationCounter.With,
        # never incremented, so each reads 0 -- for every CRD they add,
        # update or remove: v2 per CRD, v3 per served group/version, where
        # "add" means the group/version had no spec yet and an unchanged
        # version spec is no regeneration.
        def touch_regeneration(name, labels)
          CRD.metrics&.touch(name, labels)
        rescue StandardError
          nil
        end

        def openapi_before(name, group, versions)
          versions.to_h do |version|
            [version["name"], {present: @openapi.group_version_published?(group: group, version: version["name"]),
                               document: @openapi.owner_document(group: group, version: version["name"], owner: name)}]
          end
        rescue StandardError
          {}
        end

        def record_openapi_published(name, group, previously_served, before)
          touch_regeneration("apiextensions_openapi_v2_regeneration_count",
                             {"crd" => name, "reason" => previously_served ? "update" : "add"})
          before.each do |version, state|
            next if state[:document] && state[:document] == @openapi.owner_document(group: group, version: version, owner: name)

            touch_regeneration("apiextensions_openapi_v3_regeneration_count",
                               {"crd" => name, "group" => group.to_s, "version" => version, "reason" => state[:present] ? "update" : "add"})
          end
        end

        def record_openapi_removed(entry)
          touch_regeneration("apiextensions_openapi_v2_regeneration_count", {"crd" => entry.crd_name, "reason" => "remove"})
          entry.versions.each do |version|
            touch_regeneration("apiextensions_openapi_v3_regeneration_count",
                               {"crd" => entry.crd_name, "group" => entry.group.to_s, "version" => version, "reason" => "remove"})
          end
        end

        def names_conflict(crd)
          spec = crd["spec"] || {}
          names = spec["names"] || {}
          group = spec["group"]
          candidates = [names["plural"], names["singular"], *Array(names["shortNames"])].compact
          conflict = @registry.resources.find do |resource|
            next false if resource.group != group
            next false if resource.custom? && @served.values.any? do |entry|
              entry.crd_name == crd.dig("metadata", "name") && entry.names["plural"] == resource.resource
            end

            resource.resource == names["plural"] || resource.singular_name == names["singular"] || (resource.short_names & candidates).any? ||
              resource.kind == names["kind"]
          end
          return nil unless conflict

          "#{names["plural"]} conflicts with #{conflict.resource} in group #{group}"
        end

        def register_version(crd, version, storage_version)
          spec = crd["spec"] || {}
          names = spec["names"] || {}
          schema = StructuralSchema.new(
            version.dig("schema", "openAPIV3Schema") || {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true}, cel: @cel
          )
          subresources = []
          subresources << {resource: "status", verbs: %w[get patch update]} if version.dig("subresources", "status")
          if version.dig(
            "subresources", "scale"
          )
            subresources << {resource: "scale", kind: "Scale", group: "autoscaling", version: "v1",
                             verbs: %w[get patch update]}
          end
          contract = Contract.new(schema: schema, scale: version.dig("subresources", "scale"),
                                  status: !version.dig("subresources", "status").nil?)
          converter = Converter.new(crd: crd, storage_version: storage_version, webhook_client: @webhook_client, clock: @clock)
          resource = Resource.new(
            group: spec["group"], version: version["name"], resource: names["plural"], kind: names["kind"],
            scope: spec["scope"] == "Namespaced" ? :namespaced : :cluster, short_names: Array(names["shortNames"]),
            categories: Array(names["categories"]), list_kind: names["listKind"], singular_name: names["singular"],
            verbs: %w[delete deletecollection get list patch create update watch], subresources: subresources,
            schema: contract, storage_version: storage_version, converter: converter,
            storage_version_hash: crd_storage_hash(spec["group"], storage_version, names["kind"]),
            printer_columns: Array(version["additionalPrinterColumns"]),
            selectable_fields: Array(version["selectableFields"]).map { |field| field["jsonPath"] },
            custom: true
          )
          @registry.register(resource)
          @openapi.publish(group: spec["group"], version: version["name"], owner: crd.dig("metadata", "name"),
                           document: openapi_document(crd, version, schema))
        end

        def crd_storage_hash(group, version, kind)
          return unless version

          Base64.strict_encode64(Digest::SHA256.digest("#{group}/#{version}/#{kind}").byteslice(0, 8))
        end

        def conditions(_crd, accepted:, established: nil, reason: nil, message: nil)
          now = @clock.call.utc.iso8601
          list = [
            {"type" => "NamesAccepted", "status" => accepted ? "True" : "False", "reason" => accepted ? "NoConflicts" : reason,
             "message" => accepted ? "no conflicts found" : message, "lastTransitionTime" => now}
          ]
          established_value = established.nil? ? accepted : established
          list << {"type" => "Established", "status" => established_value ? "True" : "False",
                   "reason" => established_value ? "InitialNamesAccepted" : (reason || "NotAccepted"),
                   "message" => established_value ? "the initial names have been accepted" : (message || "not all names are accepted"),
                   "lastTransitionTime" => now}
          if reason == "NonStructuralSchema"
            list << {"type" => "NonStructuralSchema", "status" => "True", "reason" => "Violations", "message" => message,
                     "lastTransitionTime" => now}
          end
          list
        end

        def openapi_document(crd, version, schema)
          spec = crd["spec"] || {}
          names = spec["names"] || {}
          group = spec["group"]
          kind = names["kind"]
          plural = names["plural"]
          prefix = "#{group.split(".").reverse.join(".")}.#{version["name"]}"
          definition_name = "#{prefix}.#{kind}"
          list_kind = names["listKind"] || "#{kind}List"
          list_name = "#{prefix}.#{list_kind}"
          gvk = {"group" => group, "kind" => kind, "version" => version["name"]}
          object_schema = JSON.parse(JSON.generate(schema.schema))
          object_schema["x-kubernetes-group-version-kind"] = [gvk]
          OpenAPIMetadata.add_properties(object_schema)
          list_schema = OpenAPIMetadata.list_schema(definition_name, plural, gvk, list_kind)
          selectable = Array(version["selectableFields"]).map { |field| {"fieldPath" => field.fetch("jsonPath").delete_prefix(".")} }
          unless selectable.empty?
            object_schema["x-kubernetes-selectable-fields"] = selectable
            list_schema["x-kubernetes-selectable-fields"] = selectable
          end
          routes = OpenAPIRoutes.new(
            @openapi,
            gvk: gvk, plural: plural, definition_name: definition_name, list_name: list_name,
            namespaced: spec["scope"] == "Namespaced", subresources: version["subresources"]
          )
          {
            "openapi" => "3.0.0",
            "info" => {"title" => OpenAPIRoutes::TITLE, "version" => "v0.1.0"},
            "paths" => routes.paths,
            "components" => {"schemas" => {definition_name => object_schema, list_name => list_schema}}
          }
        end

        # Schema contract consumed by API::Server#apply_schema / validate_object!.
        class Contract
          attr_reader :schema, :scale, :status

          def initialize(schema:, scale:, status:)
            @schema = schema
            @scale = scale
            @status = status
          end

          def default(object)
            @schema.apply_defaults(@schema.prune(object))
          end

          # Server-side field validation asks the schema what it would prune.
          def unknown_fields(object)
            @schema.unknown_field_paths(object)
          end

          def validate(object, operation: :create, old: nil, **_options)
            @schema.validate(object, old: old)
            []
          rescue StructuralSchema::Invalid => error
            error.causes.map { |cause| {"field" => cause["field"], "reason" => cause["reason"], "message" => cause["message"]} }
          end

          def scale_paths
            return nil unless @scale

            {spec_replicas: @scale["specReplicasPath"], status_replicas: @scale["statusReplicasPath"],
             label_selector: @scale["labelSelectorPath"]}
          end
        end

        # Version conversion (None: apiVersion rewrite; Webhook: ConversionReview).
        class Converter
          def initialize(crd:, storage_version:, webhook_client:, clock:)
            @crd = crd
            @storage_version = storage_version
            @webhook_client = webhook_client
            @clock = clock
            @strategy = crd.dig("spec", "conversion", "strategy") || "None"
            @webhook = crd.dig("spec", "conversion", "webhook")
          end

          def group
            @crd.dig("spec", "group")
          end

          # Only the objects that are not already in the target version are
          # converted, and each one goes back where it came from.  A list read
          # from storage is not homogeneous -- a CRD whose storage version has
          # moved leaves older objects in the older version -- and upstream
          # filters the same way before calling the webhook
          # (apiextensions-apiserver conversion/webhook_converter.go
          # getObjectsToConvert: "Convert the object to the desired version"
          # only for objects whose version differs).
          #
          # +list+: the objects are a LIST's items, converted as one
          # UnstructuredList (whose own version is already the target).
          def convert(objects, to_version:, list: false)
            items = Array(objects)
            return items if items.empty?
            return timed_webhook_convert(items, to_version, list) if @strategy == "Webhook"

            convert_items(items, to_version)
          end

          def version_of(object)
            object["apiVersion"].to_s.split("/").last.to_s
          end

          private

          def convert_items(items, to_version)
            pending = items.each_index.reject { |index| version_of(items[index]) == to_version.to_s }
            return items if pending.empty?

            converted = case @strategy
                        when "None"
                          pending.map { |index| items[index].merge("apiVersion" => "#{group}/#{to_version}") }
                        when "Webhook"
                          convert_via_webhook(pending.map { |index| items[index] }, to_version)
                        else
                          raise ConversionError, "unknown conversion strategy #{@strategy}"
                        end
            result = items.dup
            pending.each_with_index { |index, position| result[index] = converted[position] }
            result
          end

          # A webhook converter's calls (webhookConverter.Convert: success,
          # including when nothing needed converting, or the failure's type)
          # and, per CRD, their duration from the input's version to the
          # target (converterMetric.Convert: an UnstructuredList is already
          # in the target version, so only single objects are observed).
          def timed_webhook_convert(items, to_version, list)
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            failure = nil
            begin
              convert_items(items, to_version)
            rescue WebhookConversionFailure => error
              failure = error
              raise ConversionError, error.message
            rescue StandardError => error
              failure = error
              raise
            ensure
              record_webhook_conversion(items, to_version, list, failure, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
            end
          end

          def record_webhook_conversion(items, to_version, list, failure, elapsed)
            metrics = CRD.metrics
            return unless metrics

            failure_type = failure.respond_to?(:failure_type) ? failure.failure_type : "conversion_webhook_call_failure"
            labels = failure ? {"result" => "failure", "failure_type" => failure_type} : {"result" => "success", "failure_type" => ""}
            metrics.increment("apiserver_conversion_webhook_request_total", labels)
            metrics.observe("apiserver_conversion_webhook_duration_seconds", elapsed, labels)
            from_version = list ? to_version.to_s : version_of(items.first)
            return if from_version == to_version.to_s

            metrics.observe("apiserver_crd_conversion_webhook_duration_seconds", elapsed,
                            {"crd_name" => @crd.dig("metadata", "name").to_s, "from_version" => from_version,
                             "to_version" => to_version.to_s, "succeeded" => failure.nil?.to_s})
          rescue StandardError
            nil
          end

          # A failed webhook conversion, by webhookConverter's failure type.
          class WebhookConversionFailure < StandardError
            attr_reader :failure_type

            def initialize(message, failure_type)
              super(message)
              @failure_type = failure_type
            end
          end

          def convert_via_webhook(objects, to_version)
            raise ConversionError, "conversion webhook client is not configured" if @webhook_client.nil?

            versions = Array(@webhook["conversionReviewVersions"])
            version = versions.find { |candidate| %w[v1 v1beta1].include?(candidate) } || "v1"
            uid = SecureRandom.uuid
            review = {"apiVersion" => "apiextensions.k8s.io/#{version}", "kind" => "ConversionReview",
                      "request" => {"uid" => uid, "desiredAPIVersion" => "#{group}/#{to_version}", "objects" => objects}}
            begin
              code, body = @webhook_client.call(@webhook.fetch("clientConfig"), review, timeout_seconds: 30)
            rescue StandardError => error
              raise WebhookConversionFailure.new(error.message, "conversion_webhook_call_failure")
            end
            fail_webhook("conversion webhook returned HTTP #{code}", "call") unless code.between?(200, 299)

            response = body.is_a?(Hash) ? body["response"] : nil
            fail_webhook("conversion webhook returned no response", "malformed_response") unless response.is_a?(Hash)
            fail_webhook("conversion webhook response UID mismatch", "malformed_response") unless response["uid"] == uid
            fail_webhook("conversion webhook failed: #{response.dig("result", "message")}", "malformed_response") unless response.dig(
              "result", "status"
            ) == "Success"

            converted = Array(response["convertedObjects"])
            unless converted.length == objects.length
              fail_webhook("conversion webhook returned #{converted.length} objects for #{objects.length}",
                           "partial_response")
            end

            converted.each_with_index do |object, index|
              original = objects[index]
              unless object["apiVersion"] == "#{group}/#{to_version}"
                fail_webhook("conversion webhook changed apiVersion",
                             "invalid_converted_object")
              end
              next if object.dig("metadata",
                                 "name") == original.dig("metadata",
                                                         "name") && object.dig("metadata", "uid") == original.dig("metadata", "uid")

              fail_webhook("conversion webhook changed metadata identity", "invalid_converted_object")
            end
            converted
          end

          def fail_webhook(message, kind)
            raise WebhookConversionFailure.new(message, "conversion_webhook_#{kind}_failure")
          end
        end
      end
    end
  end
end
