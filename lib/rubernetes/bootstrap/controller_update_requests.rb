# frozen_string_literal: true

require "uri"

module Rubernetes
  module Bootstrap
    module ControllerUpdateRequests
      def fetch_scale(descriptor, name:, namespace:)
        client.get(scale_endpoint(descriptor, name, namespace))
      rescue Client::APIError => error
        raise Controller::StoreError, error.message
      end

      private

      def apply_update(operation, fence: nil)
        return super unless operation.is_a?(Controller::Operation) && operation.subresource == "scale"

        scale = operation.object
        descriptor = operation.resource
        endpoint = scale_endpoint(descriptor, Controller::Support.name(scale), Controller::Support.namespace(scale))
        fence&.call
        result = client.update(scale, path: endpoint)
        record_effect!(descriptor: descriptor, object: scale, action: :update, response: result)
        result
      end

      def apply_strategic_patch(operation, fence: nil)
        descriptor = operation.resource
        object = operation.object
        fence&.call
        result = client.patch(descriptor.resource, operation.patch, type: :strategic, namespace: namespace_for(descriptor, object),
                                                                    api_version: descriptor.api_version, name: Controller::Support.name(object))
        record_effect!(descriptor: descriptor, object: object, action: :patch, response: result)
        write_through(descriptor, result, :update)
        result
      rescue Rubernetes::Client::APIError => error
        refresh_after_failed_update(descriptor, object, error)
        raise unless error.status.to_i == 404

        nil
      end

      def scale_endpoint(descriptor, name, namespace)
        prefix = descriptor.group.empty? ? "/api/#{descriptor.version}" : "/apis/#{descriptor.api_version}"
        prefix += "/namespaces/#{URI.encode_www_form_component(namespace)}" if descriptor.namespaced?
        "#{prefix}/#{descriptor.resource}/#{URI.encode_www_form_component(name)}/scale"
      end

      def persist_update(descriptor, candidate, current, subresource:)
        namespace = namespace_for(descriptor, candidate)
        if descriptor.kind == "Pod" && Controller::Support.current_controller == "job-controller"
          return patch_job_pod_metadata(descriptor, candidate, current, namespace)
        end

        options = {namespace: namespace}
        options[:subresource] = subresource if subresource
        options[:path] = "#{descriptor.collection_path(namespace)}/#{Controller::Support.name(candidate)}" if descriptor.is_a?(CustomResourceDescriptor)
        client.update(candidate, **options)
      end

      def apply_json_patch(operation, fence: nil)
        descriptor = operation.resource
        object = operation.object
        namespace = namespace_for(descriptor, object)
        resource = descriptor.is_a?(CustomResourceDescriptor) ? descriptor.collection_path(namespace) : descriptor.resource
        name = Controller::Support.name(object)
        fence&.call
        result = client.patch(resource, operation.patch, type: :json, namespace: namespace, api_version: descriptor.api_version, name: name)
        record_effect!(descriptor: descriptor, object: object, action: :patch, response: result)
        write_through(descriptor, result, :update)
        result
      end

      # The Job controller claims and releases Pods and removes its tracking
      # finalizer with PATCH. Its upstream role grants pods/patch. Limit the
      # request to those metadata fields and carry the plan's preconditions.
      def patch_job_pod_metadata(descriptor, candidate, current, namespace)
        metadata = Controller::Support.metadata(candidate)
        previous = Controller::Support.metadata(current)
        changed = %w[finalizers ownerReferences].reject { |field| metadata[field] == previous[field] }
        return current if changed.empty?

        patch = metadata.slice("uid", "resourceVersion").merge(changed.to_h { |field| [field, metadata[field]] })
        client.patch(descriptor.resource, {"metadata" => patch}, type: :merge, namespace: namespace,
                                                                 api_version: descriptor.api_version,
                                                                 name: Controller::Support.name(candidate))
      end
    end
  end
end
