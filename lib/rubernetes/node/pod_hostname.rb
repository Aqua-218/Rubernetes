# frozen_string_literal: true

module Rubernetes
  module Node
    # kubelet GeneratePodHostNameAndDomain + util.GetNodenameForKernel: the
    # Pod's hostname and domain (/etc/hosts), and the UTS hostname
    # (/etc/hostname), which setHostnameAsFQDN makes the FQDN.
    # spec.hostnameOverride (HostnameOverride, Beta, on) replaces both the
    # name and the domain.
    module PodHostname
      class Error < StandardError; end

      HOSTNAME_MAX = 63
      # The Linux nodename field: 64 characters and the terminating NUL.
      FQDN_MAX = 64

      module_function

      # [hostname, domain]; the domain is empty without spec.subdomain.
      def generate(pod, cluster_domain:)
        spec = key(pod, "spec") || {}
        metadata = key(pod, "metadata") || {}
        name = key(metadata, "name").to_s
        override = key(spec, "hostnameOverride")
        return [truncate(name, override.to_s), ""] unless override.nil?

        hostname = key(spec, "hostname").to_s.empty? ? name : key(spec, "hostname").to_s
        subdomain = key(spec, "subdomain").to_s
        namespace = key(metadata, "namespace") || "default"
        [truncate(name, hostname), subdomain.empty? ? "" : "#{subdomain}.#{namespace}.svc.#{cluster_domain}"]
      end

      def kernel_hostname(pod, cluster_domain:)
        hostname, domain = generate(pod, cluster_domain: cluster_domain)
        return hostname unless !domain.empty? && key(key(pod, "spec") || {}, "setHostnameAsFQDN") == true

        fqdn = "#{hostname}.#{domain}"
        if fqdn.length > FQDN_MAX
          raise Error, "failed to construct FQDN from pod hostname and cluster domain, FQDN #{fqdn} is too long " \
                       "(#{FQDN_MAX} characters is the max, #{fqdn.length} characters requested)"
        end
        fqdn
      end

      def key(hash, name)
        return unless hash.is_a?(Hash)

        hash.key?(name) ? hash[name] : hash[name.to_sym]
      end

      # truncatePodHostnameIfNeeded: 63 characters, no trailing '-' or '.'.
      def truncate(pod_name, hostname)
        return hostname if hostname.length <= HOSTNAME_MAX

        truncated = hostname[0, HOSTNAME_MAX].sub(/[-.]+\z/, "")
        raise Error, "hostname for pod #{pod_name.inspect} was invalid: #{hostname.inspect}" if truncated.empty?

        truncated
      end
    end
  end
end
