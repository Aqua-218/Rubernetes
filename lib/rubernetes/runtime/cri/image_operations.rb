# frozen_string_literal: true

module Rubernetes
  module Runtime
    module CRI
      module ImageOperations
        # Node::Agent builds the kubelet's image GC over the runtime from it.
        def image_gc_source = true

        def ensure_image(image, spec = {}, pod: nil, sandbox_config: nil, runtime_class_name: pod&.dig("spec", "runtimeClassName"))
          image_spec = {"image" => image}
          image_spec["runtime_handler"] = @handler if @runtime_class_in_image_api && !runtime_class_name.to_s.empty?
          policy = spec["imagePullPolicy"].to_s
          unless policy == "Always"
            present = @client.image("ImageStatus", {"image" => image_spec})["image"]
            return present if present && !present.fetch("id", "").to_s.empty?
            raise Backend::Error, "image #{image.inspect} is not present with pull policy Never" if policy == "Never"
          end

          request = {"image" => image_spec}
          request["sandbox_config"] = sandbox_config if sandbox_config
          auth = pull_auth(pod, image)
          request["auth"] = auth if auth
          @pull_limiter.synchronize { @client.image("PullImage", request, timeout: 600) }
        end

        private

        # PullImageRequest.auth (AuthConfig) from the Pod's credentials.
        def pull_auth(pod, image)
          return nil if @credential_provider.nil? || pod.nil?

          credential = @credential_provider.call(pod, image)
          return nil if credential.nil?

          credential = credential.to_h.transform_keys(&:to_s)
          {"username" => credential["username"].to_s, "password" => credential["password"].to_s,
           "server_address" => credential["registry"].to_s, "identity_token" => credential["identity_token"].to_s}
            .reject { |_name, value| value.empty? }
        end
      end
    end
  end
end
