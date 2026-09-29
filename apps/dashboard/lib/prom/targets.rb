# frozen_string_literal: true

require "yaml"
require "json"
require_relative "target"

module Prom
  # Service discovery for a Rubernetes cluster, in the spirit of the
  # kubernetes_sd_configs a stock Prometheus uses against Kubernetes:
  #   * job "apiserver": every API server process of the cluster, on its
  #     own port with the kubeconfig credentials;
  #   * jobs "kubelet", "cadvisor", "kubelet-resource", "kubelet-probes":
  #     each node's /metrics endpoints through the API server proxy;
  #   * job "kubernetes-pods": Pods annotated prometheus.io/scrape=true
  #     (port and path from prometheus.io/port and prometheus.io/path),
  #     reached at their Pod IP;
  #   * job "kubernetes-service-endpoints": Services annotated the same way,
  #     via each ready EndpointSlice endpoint.
  class Targets
    KUBELET_PATHS = {
      "kubelet" => "metrics",
      "cadvisor" => "metrics/cadvisor",
      "kubelet-resource" => "metrics/resource",
      "kubelet-probes" => "metrics/probes"
    }.freeze

    def initialize(client:, cluster_json: {}, kubeconfig_context: nil, http: nil)
      @client = client
      @cluster_json = cluster_json
      @kubeconfig_context = kubeconfig_context
      @http = http || method(:plain_http_fetch)
    end

    def discover
      apiserver_targets + kubelet_targets + pod_targets + service_targets
    end

    def apiserver_targets
      processes = Array(@cluster_json["processes"]).select { |p| p["executable"] == "rubernetes-apiserver" }
      processes.filter_map do |process|
        port = apiserver_port(process["config"])
        next if port.nil?

        server = "https://127.0.0.1:#{port}"
        client = apiserver_client(server)
        next if client.nil?

        Target.new(job: "apiserver", instance: "127.0.0.1:#{port}", labels: {"process" => process["name"].to_s},
                   url: "#{server}/metrics", fetch: -> { api_fetch(client, "/metrics") })
      end
    end

    def kubelet_targets
      nodes = safe_list("nodes")
      nodes.flat_map do |node|
        name = node.dig("metadata", "name").to_s
        KUBELET_PATHS.map do |job, path|
          Target.new(job: job, instance: name, labels: {"node" => name},
                     url: "#{server_url}/api/v1/nodes/#{name}/proxy/#{path}",
                     fetch: -> { api_fetch(@client, "/api/v1/nodes/#{name}/proxy/#{path}") })
        end
      end
    end

    def pod_targets
      safe_list("pods", all_namespaces: true).filter_map do |pod|
        annotations = pod.dig("metadata", "annotations") || {}
        next unless annotations["prometheus.io/scrape"].to_s == "true"

        ip = pod.dig("status", "podIP").to_s
        next if ip.empty? || pod.dig("status", "phase") != "Running"

        port = annotations["prometheus.io/port"].to_s
        port = first_container_port(pod) if port.empty?
        next if port.empty?

        path = annotations.fetch("prometheus.io/path", "/metrics")
        path = "/#{path}" unless path.start_with?("/")
        scheme = annotations.fetch("prometheus.io/scheme", "http")
        url = "#{scheme}://#{format_host(ip)}:#{port}#{path}"
        Target.new(job: "kubernetes-pods", instance: "#{format_host(ip)}:#{port}",
                   labels: {"namespace" => pod.dig("metadata", "namespace").to_s, "pod" => pod.dig("metadata", "name").to_s,
                            "node" => pod.dig("spec", "nodeName").to_s},
                   url: url, fetch: -> { @http.call(url) })
      end
    end

    def service_targets
      services = safe_list("services", all_namespaces: true).select do |service|
        (service.dig("metadata", "annotations") || {})["prometheus.io/scrape"].to_s == "true"
      end
      return [] if services.empty?

      slices = safe_list("endpointslices", all_namespaces: true, api_version: "discovery.k8s.io/v1")
      services.flat_map do |service|
        annotations = service.dig("metadata", "annotations") || {}
        namespace = service.dig("metadata", "namespace").to_s
        name = service.dig("metadata", "name").to_s
        path = annotations.fetch("prometheus.io/path", "/metrics")
        path = "/#{path}" unless path.start_with?("/")
        scheme = annotations.fetch("prometheus.io/scheme", "http")
        owned = slices.select do |slice|
          slice.dig("metadata", "namespace") == namespace && slice.dig("metadata", "labels", "kubernetes.io/service-name") == name
        end
        owned.flat_map do |slice|
          port = annotations["prometheus.io/port"].to_s
          port = Array(slice["ports"]).first&.dig("port").to_s if port.empty?
          next [] if port.empty?

          Array(slice["endpoints"]).flat_map do |endpoint|
            next [] unless endpoint.dig("conditions", "ready") != false

            Array(endpoint["addresses"]).map do |address|
              url = "#{scheme}://#{format_host(address)}:#{port}#{path}"
              Target.new(job: "kubernetes-service-endpoints", instance: "#{format_host(address)}:#{port}",
                         labels: {"namespace" => namespace, "service" => name,
                                  "pod" => endpoint.dig("targetRef", "name").to_s, "node" => endpoint["nodeName"].to_s},
                         url: url, fetch: -> { @http.call(url) })
            end
          end
        end
      end
    end

    private

    def server_url
      context = @kubeconfig_context
      return "https://apiserver" if context.nil?

      (context.respond_to?(:server) ? context.server : (context[:server] || context["server"])) || "https://apiserver"
    end

    def safe_list(resource, all_namespaces: false, api_version: "v1")
      # The client defaults to the kubeconfig namespace; :all lists cluster-wide.
      response = if all_namespaces
                   @client.get(resource, namespace: :all, api_version: api_version)
                 else
                   @client.get(resource, api_version: api_version)
                 end
      Array(response["items"])
    rescue StandardError
      []
    end

    def first_container_port(pod)
      Array(pod.dig("spec", "containers")).each do |container|
        Array(container["ports"]).each { |port| return port["containerPort"].to_s if port["containerPort"] }
      end
      ""
    end

    def format_host(address)
      address.include?(":") ? "[#{address}]" : address
    end

    def apiserver_port(config_path)
      return nil unless config_path && File.file?(config_path)

      document = YAML.safe_load(File.read(config_path), aliases: true, permitted_classes: [Symbol]) || {}
      process = document.dig("processes", "rubernetes-apiserver") || {}
      port = process["port"] || process.dig("listen", "port")
      port&.to_i
    rescue StandardError
      nil
    end

    def apiserver_client(server)
      return nil if @kubeconfig_context.nil?

      require "rubernetes/client"
      context = @kubeconfig_context.merge(server: server)
      Rubernetes::Client::HTTPClient.new(context: context)
    rescue StandardError
      nil
    end

    def api_fetch(client, path)
      response = client.respond_to?(:raw) ? client.raw(:get, path, raise_for_status: false) : client.request("GET", path)
      [response.status.to_i, response.body.to_s]
    end

    def plain_http_fetch(url)
      require "net/http"
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl?
      http.open_timeout = 5
      http.read_timeout = 10
      response = http.get(uri.request_uri, {"Accept" => "text/plain;version=0.0.4"})
      [response.code.to_i, response.body.to_s]
    end
  end
end
