# frozen_string_literal: true

require_relative "k6_corpus"
require_relative "../../lib/rubernetes/schema/quantity"

module Conformance
  # Stock HPA resource tests need live kubelet metrics. Only an explicitly
  # requested, freshly provisioned fixture is installed by this helper.
  module K3HPAMetrics
    NAME = "metrics-server"
    APISERVICE = "v1beta1.metrics.k8s.io"
    NODE_METRICS = "/apis/metrics.k8s.io/v1beta1/nodes"
    KUBELET_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    HELM = File.join(K6Corpus::ROOT, "build/tools/clients/helm")
    KUBECTL = File.join(K6Corpus::ROOT, "build/tools/kubectl-v1.36.2")

    module_function

    def install(descriptor, nodes)
      corpus = YAML.safe_load_file(K6Corpus::CORPUS)
      project = corpus.fetch("projects").find { |entry| entry.fetch("name") == NAME }
      kubeconfig = descriptor.fetch("kubeconfig")
      Dir.mktmpdir("k3-metrics-server") do |directory|
        env = %w[CONFIG CACHE DATA].to_h { |kind| ["HELM_#{kind}_HOME", File.join(directory, kind.downcase)] }
        package = prepare_chart(corpus.fetch("repositories"), project, directory, env)
        image = project.fetch("images").fetch(0)
        install_chart(env, package, image, kubeconfig)
        metrics = wait_for_node_metrics(kubeconfig, nodes)
        log = File.join(descriptor.fetch("root"), "logs", "hpa-node-metrics.json")
        File.write(log, "#{JSON.pretty_generate(metrics)}\n")
        {"chart_sha256" => project.fetch("chart_sha256"), "image" => image, "node_metrics" => log}
      end
    end

    def prepare_chart(repositories, project, directory, env)
      options = {helm_env: env, path: ENV.fetch("PATH", ""), chart_directory: directory}
      results = K6Corpus.prepare_repositories(repositories, [project], options)
      failures = results.reject { |entry| entry.fetch("passed") }
      raise "metrics-server chart preparation failed: #{failures}" unless failures.empty?

      File.join(directory, project.fetch("chart_package"))
    end

    def install_chart(env, package, image, kubeconfig)
      reference, digest = image.split("@", 2)
      repository, _, tag = reference.rpartition(":")
      run!(env, HELM, "install", NAME, package, "--kubeconfig", kubeconfig, "--namespace", "kube-system",
           "--set-string", "image.repository=#{repository}", "--set-string", "image.tag=#{tag}@#{digest}",
           "--set-string", "args[0]=--kubelet-certificate-authority=#{KUBELET_CA}", "--wait", "--timeout", "5m")
      run!({}, KUBECTL, "--kubeconfig", kubeconfig, "wait", "--for=condition=Available", "apiservice/#{APISERVICE}", "--timeout=90s")
    end

    def wait_for_node_metrics(kubeconfig, nodes)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 90
      loop do
        output, _error, status = Open3.capture3(KUBECTL, "--kubeconfig", kubeconfig, "--request-timeout=10s",
                                                "get", "--raw", NODE_METRICS)
        if status.success?
          metrics = JSON.parse(output)
          observed = metrics.fetch("items").select { |item| measured?(item) }.map { |item| item.dig("metadata", "name") }
          return metrics if observed.sort == nodes.sort
        end
        break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep 2
      end
      raise "metrics-server returned no complete CPU and memory samples for #{nodes.join(", ")}"
    end

    def measured?(item)
      return false if item["window"].to_s.empty? || item["timestamp"].to_s.empty?

      %w[cpu memory].all? do |resource|
        Rubernetes::Schema::Quantity.from_json(item.dig("usage", resource)).sign.positive?
      end
    rescue Rubernetes::Schema::Quantity::ParseError
      false
    end

    def run!(env, *command)
      output, error, status = Open3.capture3(env, *command)
      raise "#{File.basename(command.first)} failed: #{error.strip}" unless status.success?

      output
    end
  end
end
