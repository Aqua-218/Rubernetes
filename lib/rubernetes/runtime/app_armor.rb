# frozen_string_literal: true

module Rubernetes
  module Runtime
    # Resolves the v1 field and the legacy per-container annotation, including
    # static Pods whose annotations were never normalized by the API server.
    module AppArmor
      ANNOTATION_PREFIX = "container.apparmor.security.beta.kubernetes.io/"
      GROUPS = %w[initContainers containers ephemeralContainers].freeze

      module_function

      def profile(pod, container)
        container.dig("securityContext", "appArmorProfile") || annotation_profile(pod, container["name"]) ||
          pod.dig("spec", "securityContext", "appArmorProfile")
      end

      def required?(pod)
        return true if enforced?(pod.dig("spec", "securityContext", "appArmorProfile"))

        containers(pod).any? { |container| enforced?(profile(pod, container)) }
      end

      def enforced?(profile) = profile && profile["type"] != "Unconfined"

      def containers(pod)
        GROUPS.flat_map { |group| Array(pod.dig("spec", group)) }
      end

      def kernel_enabled?
        File.directory?("/sys/kernel/security/apparmor") && File.read("/sys/module/apparmor/parameters/enabled").start_with?("Y")
      rescue SystemCallError
        false
      end

      def cri_profile(profile)
        case profile.fetch("type")
        when "RuntimeDefault", "Unconfined"
          {"profile_type" => profile.fetch("type")}
        when "Localhost"
          reference = profile["localhostProfile"].to_s
          raise ArgumentError, "AppArmor Localhost profile requires a profile name" if reference.strip.empty?

          {"profile_type" => "Localhost", "localhost_ref" => reference}
        else
          raise ArgumentError, "unsupported AppArmor profile type"
        end
      end

      def annotation_profile(pod, name)
        value = pod.dig("metadata", "annotations", "#{ANNOTATION_PREFIX}#{name}")
        return if value.nil?

        case value
        when "runtime/default" then {"type" => "RuntimeDefault"}
        when "unconfined" then {"type" => "Unconfined"}
        when %r{\Alocalhost/} then {"type" => "Localhost", "localhostProfile" => value.delete_prefix("localhost/")}
        else {"type" => "Invalid"}
        end
      end
    end
  end
end
