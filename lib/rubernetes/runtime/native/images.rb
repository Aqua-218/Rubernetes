# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # Image identity: resolves the image references of a sandbox and of each
      # container to pinned digests, derives the container's command,
      # environment and working directory from the image config, and verifies
      # the pinned identity before any filesystem effect.
      module Images
        private

        # Resolve direct runtime callers as well as the Node lifecycle path. The
        # latter supplies `resolved_images`; direct callers with an image must
        # inject the same resolver explicitly, otherwise the runtime fails before
        # it creates a sandbox record or touches a host adapter.
        def resolve_images(input)
          resolved = Array(input["resolved_images"] || input[:resolved_images])
          references = []
          references << input["image"] if input["image"] || input[:image]
          spec = input["spec"] || input[:spec]
          if spec.is_a?(Hash)
            Array(spec["initContainers"] || spec[:initContainers]).each { |container| references << normalize_hash(container)["image"] }
            Array(spec["containers"] || spec[:containers]).each { |container| references << normalize_hash(container)["image"] }
          end
          references = references.compact.reject { |value| value.to_s.empty? }
          if resolved.empty? && references.any?
            raise FailClosed, "image resolver is required for a sandbox with image references" unless @image_resolver

            resolved = references.map { |reference| normalize_resolved_image(resolve_image_reference(reference), reference) }
          else
            resolved = resolved.map { |value| normalize_resolved_image(value) }
          end
          return input if resolved.empty?

          input["resolved_images"] = resolved
          input["image_digest"] ||= aggregate_image_digest(resolved)
          roots = resolved.filter_map { |image| image["rootfs"] }.uniq
          input["lowerdirs"] = (Array(input["lowerdirs"] || input[:lowerdirs]) + roots).compact.uniq
          input
        end

        def normalize_resolved_image(value, reference = nil)
          image = normalize_hash(value)
          digest = image["digest"]
          raise FailClosed, "image resolver returned an invalid pinned digest" unless digest.to_s.match?(/\Asha256:[0-9a-fA-F]{64}\z/)

          image["digest"] = digest.to_s.downcase
          unless reference.nil?
            image["reference"] ||= reference.to_s
            image["requested_reference"] ||= reference.to_s
          end
          image
        end

        def aggregate_image_digest(images)
          digests = images.map { |image| image.fetch("digest") }.uniq.sort
          "sha256:#{Digest::SHA256.hexdigest(JSON.generate(digests))}"
        end

        def resolve_container_spec(input, sandbox: nil)
          resolved = input["resolved_image"] || input[:resolved_image]
          if resolved.nil? && input["image"] && sandbox
            candidates = Array(sandbox.config["resolved_images"])
            resolved = candidates.find do |candidate|
              candidate["requested_reference"].to_s == input["image"].to_s || candidate["reference"].to_s == input["image"].to_s
            end
            resolved ||= candidates.fetch(0) if candidates.length == 1
          end
          raise FailClosed, "container image was not resolved before container creation" if input["image"] && resolved.nil?
          return input unless resolved

          resolved = normalize_resolved_image(resolved, input["image"])
          input["resolved_image"] = resolved
          input["image_digest"] = resolved["digest"]
          input["rootfs_path"] = resolved["rootfs"] if resolved["rootfs"]
          image_entrypoint = Array(resolved["entrypoint"])
          image_command = Array(resolved["cmd"])
          command = if input.key?("command") || input.key?("argv")
                      input["command"] || input["argv"]
                    elsif input.key?("args")
                      image_entrypoint + normalize_argv(input["args"], "container args")
                    else
                      resolved["command"] || (image_entrypoint + image_command)
                    end
          input["command"] = command unless command.nil?
          input["env"] = merge_environment(resolved["env"], input["env"])
          input["cwd"] = input["workingDir"] || resolved["working_dir"] if input["workingDir"] || resolved["working_dir"]
          input
        end

        def pin_image(input)
          digest = input["image_digest"] || input[:image_digest] || config.image["digest"]
          bytes = input["image_bytes"] || input[:image_bytes]
          verified = false
          image_adapter = @adapters[:image]
          image_adapter ||= default_image_verifier if config.host_profile? && bytes.nil? && Array(input["resolved_images"]).any?
          if image_adapter
            result = invoke(image_adapter, :verify, image: input, digest: digest, bytes: bytes)
            unless result == true || result == digest || result == digest&.downcase
              raise FailClosed,
                    "image adapter did not confirm digest verification"
            end

            verified = true
          end
          if bytes && digest
            Filesystem.new.verify_digest(bytes, digest)
            verified = true
          end
          raise FailClosed, "production Native runtime requires image bytes or an adapter-verified OCI identity" if config.host_profile? && !verified

          if digest
            String(digest).downcase
          elsif config.host_profile? || input["image"] || input["resolved_images"]
            raise FailClosed, "production Native runtime requires a verified OCI image identity"
          else
            # Pure/fake profiles intentionally support an image-less state
            # machine test.  This fixed test identity is never accepted by a
            # host profile and is not derived from mutable request input.
            "sha256:#{Digest::SHA256.hexdigest("rubernetes-pure-test-image-v1")}"
          end
        end

        # Host profiles verify pinned OCI manifests with the production image
        # verifier when the caller did not inject one; a resolver result is
        # never trusted on the strength of its digest string alone.
        def default_image_verifier
          require_relative "../../image/verifier"
          @default_image_verifier ||= Rubernetes::Image::PinnedImageVerifier.new
        end
      end
    end
  end
end
