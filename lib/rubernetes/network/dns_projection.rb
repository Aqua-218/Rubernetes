# frozen_string_literal: true

require "fileutils"
require "securerandom"

require_relative "../node/pod_files"
require_relative "errors"
require_relative "support"

module Rubernetes
  module Network
    module DNS
      # Projects the kubelet resolver configuration into a caller-selected file.
      module Projection
        SYSTEM_RESOLV_CONF = "/etc/resolv.conf"
        DEFAULT_HOST_RESOLVER = Object.new.freeze

        # Standalone projection applies its path and upstream address checks
        # around the same DNS composition used for kubelet Pod files.
        class PodDNSProjection < Node::PodFiles
          def initialize(check_source:, validate_server:, **)
            super(**)
            @check_source = check_source
            @validate_server = validate_server
          end

          private

          def read_resolver(path)
            super(@check_source.call(path))
          end

          def host_dns
            config = super
            config["servers"] = config.fetch("servers").map(&@validate_server).uniq if @validate_server
            config
          end
        end
        private_constant :PodDNSProjection, :DEFAULT_HOST_RESOLVER, :SYSTEM_RESOLV_CONF

        # Render the pod's resolv.conf in a temporary file and atomically swap
        # it into place.  The target itself may not be a symlink.
        def project_resolv_conf(path:, namespace: "default", dns_policy: "ClusterFirst",
                                dns_config: nil, host_network: false, host_resolv_conf: DEFAULT_HOST_RESOLVER,
                                cluster_ip: @cluster_ip, node_ips: [], fsync: true, **_options)
          target = safe_projection_path(path)
          policy = String(dns_policy || "ClusterFirst")
          raise DNSProjectionError, "unsupported dnsPolicy #{policy.inspect}" unless %w[None Default ClusterFirst ClusterFirstWithHostNet].include?(policy)

          config = normalize_projection_overrides(dns_config)
          raise DNSProjectionError, "dnsConfig.nameservers is required for dnsPolicy None" if policy == "None" && config.fetch("nameservers").empty?

          projection = pod_dns_projection(policy, host_resolv_conf, cluster_ip, host_network)
          pod = {"metadata" => {"namespace" => namespace}, "spec" => {"dnsPolicy" => policy, "dnsConfig" => config}}
          content = projection.resolv_conf_content(pod, host_network: host_network, node_ips: node_ips)
          atomic_write(target, content, fsync: fsync)
          content
        rescue DNSProjectionError
          raise
        rescue StandardError => error
          raise DNSProjectionError, "resolv.conf projection failed: #{error.message}"
        end

        alias project_resolv_conf! project_resolv_conf
        alias write_resolv_conf project_resolv_conf

        private

        def safe_projection_path(path)
          target = File.expand_path(String(path))
          raise DNSProjectionError, "resolv.conf target is a directory" if File.directory?(target)
          raise DNSProjectionError, "resolv.conf target must not be a symlink" if File.symlink?(target)

          relative = target.delete_prefix("/").split("/")
          current = "/"
          relative[0...-1].each do |component|
            current = File.join(current, component)
            raise DNSProjectionError, "resolv.conf parent path must not contain symlinks" if File.symlink?(current)
          end
          target
        rescue TypeError
          raise DNSProjectionError, "resolv.conf path must be a string"
        end

        def normalize_projection_overrides(dns_config)
          config = object_fields(dns_config) || {}
          nameservers = Array(Support.fetch(config, "nameservers", default: [])).map { |server| validate_upstream(server) }
          search = Array(Support.fetch(config, "searches", "search", default: [])).map { |entry| normalize_domain(entry) }
          options = Array(Support.fetch(config, "options", default: [])).map do |entry|
            hash = object_fields(entry)
            name = Support.string(Support.fetch(hash, "name"), "resolv.conf option")
            value = Support.fetch(hash, "value", default: nil)
            {"name" => name, "value" => (Support.string(value, "resolv.conf option value", allow_empty: true) if value)}.compact
          end
          {"nameservers" => nameservers, "searches" => search, "options" => options}
        end

        def pod_dns_projection(policy, host_resolv_conf, cluster_ip, host_network)
          system = host_resolv_conf.equal?(DEFAULT_HOST_RESOLVER)
          resolver = system ? SYSTEM_RESOLV_CONF : String(host_resolv_conf) unless policy == "None"
          cluster = policy == "ClusterFirstWithHostNet" || (policy == "ClusterFirst" && !host_network)
          servers = cluster ? [Support.ip(cluster_ip, name: "cluster DNS IP").to_s] : []
          PodDNSProjection.new(cluster_dns: servers, cluster_domain: @domain, resolv_conf: resolver.to_s,
                               check_source: ->(path) { safe_host_resolver_path(path, system: system) },
                               validate_server: (method(:validate_upstream) unless cluster))
        end

        def safe_host_resolver_path(path, system:)
          source = File.expand_path(String(path))
          # The OS's default may be a symlink to its resolver stub. A path
          # selected by the caller still has to pass the explicit checks.
          source = File.realpath(source) if system && source == SYSTEM_RESOLV_CONF
          raise DNSProjectionError, "host resolv.conf must not be a symlink" if File.symlink?(source)

          validate_parent_path!(File.dirname(source))
          source
        rescue SystemCallError => error
          raise DNSProjectionError, "cannot read host resolv.conf: #{error.message}"
        end

        def atomic_write(path, content, fsync:)
          directory = File.dirname(path)
          FileUtils.mkdir_p(directory)
          validate_parent_path!(directory)
          raise DNSProjectionError, "resolv.conf target must not be a symlink" if File.symlink?(path)

          temporary = "#{path}.tmp-#{Process.pid}-#{SecureRandom.hex(8)}"
          File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
            file.write(content)
            file.flush
            file.fsync if fsync
          end
          File.rename(temporary, path)
          directory_handle = File.open(directory, File::RDONLY)
          directory_handle.fsync if fsync
          true
        ensure
          directory_handle&.close
          File.delete(temporary) if temporary && File.exist?(temporary)
        end

        def validate_parent_path!(directory)
          absolute = File.expand_path(directory)
          components = absolute.delete_prefix("/").split("/")
          current = "/"
          components.each do |component|
            current = File.join(current, component)
            raise DNSProjectionError, "resolv.conf parent path must not contain symlinks" if File.symlink?(current)
          end
        end
      end
    end
  end
end
