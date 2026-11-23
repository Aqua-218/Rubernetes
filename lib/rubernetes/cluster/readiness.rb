# frozen_string_literal: true

module Rubernetes
  module Cluster
    # Waiting for what was started.
    module Readiness
      # Anonymous auth is off, so /readyz answers 401 without a client
      # certificate: the probe goes through a kubeconfig, never a bare GET.
      def api_ready?(kubeconfig)
        client = api_client(kubeconfig)
        client.raw("GET", "/readyz", raise_for_status: false).status == 200
      rescue Client::Error, SystemCallError, OpenSSL::SSL::SSLError
        false
      ensure
        client&.close
      end

      def stored?(kubeconfig, path)
        client = api_client(kubeconfig)
        client.raw("GET", path, raise_for_status: false).status == 200
      rescue Client::Error, SystemCallError, OpenSSL::SSL::SSLError
        false
      ensure
        client&.close
      end

      # The Node objects of a restarted cluster still say Ready from before
      # the stop; with `since`, only a heartbeat written after it counts.
      def ready_nodes(kubeconfig, since: nil)
        client = api_client(kubeconfig)
        JSON.parse(client.raw("GET", "/api/v1/nodes").body).fetch("items", []).count do |node|
          node.dig("status", "conditions")&.any? do |condition|
            condition["type"] == "Ready" && condition["status"] == "True" &&
              (since.nil? || Time.iso8601(condition.fetch("lastHeartbeatTime")) >= since)
          end
        end
      rescue Client::Error, SystemCallError, OpenSSL::SSL::SSLError, JSON::ParserError
        0
      ensure
        client&.close
      end

      def pod_cidrs_published?(kubeconfig, assignments)
        client = api_client(kubeconfig)
        nodes = JSON.parse(client.raw("GET", "/api/v1/nodes").body).fetch("items", []).to_h do |node|
          [node.dig("metadata", "name"), node["spec"]]
        end
        assignments.all? do |name, ranges|
          spec = nodes[name]
          spec && spec["podCIDR"] == ranges.first && spec["podCIDRs"] == ranges
        end
      rescue Client::Error, SystemCallError, OpenSSL::SSL::SSLError, JSON::ParserError
        false
      ensure
        client&.close
      end

      def await!(what)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + ready_timeout
        until yield
          raise Error, "#{what} did not become ready within #{ready_timeout}s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

          sleep(0.25)
        end
        true
      end

      def api_client(kubeconfig)
        Client::KubernetesClient.from_kubeconfig(path: kubeconfig, env: {}, open_timeout: 2, read_timeout: 10, max_retries: 0)
      end
    end
  end
end
