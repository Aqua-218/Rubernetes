# frozen_string_literal: true

require "digest"
require "json"
require "net/http"
require "securerandom"
require "timeout"

require_relative "lanes"

module Conformance
  # Runs a checksum-verified kubectl against a fresh workload for each case in
  # the version matrix. Only that workload's namespace is changed.
  class K6ClientVerbs
    IMAGE = Lock.reference_by_digest(Lock.support_images.fetch("busybox"))
    WEB = "deployment/k6-web"
    ATTACH = "pod/k6-attach"
    LOG_LINE = "k6 web started"
    HTTP_BODY = "k6 forwarded response"
    TOKEN = "k6-client-token"

    def initialize(binary:, kubeconfig:, image:)
      @binary = binary
      @kubeconfig = kubeconfig
      @image = image
      @namespace = "k6-client-#{SecureRandom.hex(6)}"
    end

    def run
      result = {"namespace" => @namespace, "image" => @image, "verbs" => []}
      begin
        create = command(%W[create namespace #{@namespace}])
        unless successful?(create)
          result["reason"] = diagnostic(create)
          return result
        end

        result["verbs"].concat(api_verbs)
        setup = command(%w[create -f -], input: workload)
        result["setup"] = setup.slice("command", "exit_status", "stderr")
        result["verbs"].concat(workload_verbs)
      ensure
        cleanup = command(%W[delete namespace #{@namespace} --ignore-not-found --wait=true --timeout=90s], timeout: 100)
        result["cleanup"] = cleanup.slice("command", "exit_status", "stderr")
        result["passed"] = !setup.nil? && successful?(setup) && successful?(cleanup) &&
                           result.fetch("verbs").all? { |verb| verb.fetch("passed") }
      end
      result
    end

    private

    def api_verbs
      [
        probe(%w[api-resources --no-headers]) { |out| out.match?(/^pods\s/) && out.match?(/^deployments\s/) },
        probe(%w[explain pod.spec]) { |out| out.match?(/^KIND:\s+Pod\b/) },
        probe(%W[get namespace #{@namespace} -o json]) { |out| JSON.parse(out).dig("metadata", "name") == @namespace },
        probe(%w[create configmap k6-model --from-literal=state=created -o json]) { |out| state?(out, "created") },
        probe(%w[get configmap k6-model -o json]) { |out| state?(out, "created") }.merge("verb" => "get object"),
        probe(%w[get configmaps -o json]) do |out|
          JSON.parse(out).fetch("items").any? { |item| item.dig("metadata", "name") == "k6-model" }
        end.merge("verb" => "list"),
        watch,
        probe(%w[apply -f - --server-side --field-manager=k6-client -o json],
              input: configmap("k6-applied", "applied")) { |out| state?(out, "applied") },
        probe(%w[diff -f - --server-side --field-manager=k6-client],
              expected_exit: 1, input: configmap("k6-applied", "different")) do |out|
          out.include?("-  state: applied") && out.include?("+  state: different")
        end,
        probe(%w[patch configmap k6-model --type=merge -p] + ['{"data":{"state":"patched"}}', "-o", "json"]) { |out| state?(out, "patched") },
        probe(%w[replace -f - -o json], input: configmap("k6-model", "replaced")) { |out| state?(out, "replaced") },
        delete,
        probe(%w[auth can-i get pods]) { |out| out.strip == "yes" }
      ]
    end

    def workload_verbs
      [
        probe(%W[rollout status #{WEB} --timeout=100s], timeout: 110) { |out| out.include?("successfully rolled out") },
        probe(%W[wait --for=condition=Ready #{ATTACH} --timeout=100s], timeout: 110) { |out| out.include?("condition met") },
        probe(%W[logs #{WEB}]) { |out| out.lines.map(&:strip).include?(LOG_LINE) },
        probe(%W[exec #{WEB} -- /bin/busybox cat /tmp/k6-www/index.html]) { |out| out.strip == HTTP_BODY },
        probe(%W[attach --stdin --quiet #{ATTACH}], input: "#{TOKEN}\n") { |out| out.lines.map(&:strip).include?("attached:#{TOKEN}") },
        port_forward,
        scale,
        top
      ]
    end

    def configmap(name, state)
      JSON.generate({"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"namespace" => @namespace, "name" => name},
                     "data" => {"state" => state}})
    end

    def workload
      labels = {"app" => "k6-web"}
      web = <<~SH
        /bin/busybox mkdir -p /tmp/k6-www
        printf '%s\n' '#{HTTP_BODY}' > /tmp/k6-www/index.html
        printf '%s\n' '#{LOG_LINE}'
        exec /bin/busybox httpd -f -p 8080 -h /tmp/k6-www
      SH
      deploy = {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => "k6-web"},
                "spec" => {"selector" => {"matchLabels" => labels},
                           "template" => {"metadata" => {"labels" => labels}, "spec" => pod_spec(web)}}}
      attach = 'IFS= read -r input; printf "attached:%s\n" "$input"'
      pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "k6-attach"},
             "spec" => pod_spec(attach, "stdin" => true, "stdinOnce" => true).merge("restartPolicy" => "Never")}
      JSON.generate({"apiVersion" => "v1", "kind" => "List", "items" => [deploy, pod]})
    end

    def pod_spec(script, interactive = {})
      {"automountServiceAccountToken" => false,
       "containers" => [{"name" => "busybox", "image" => @image, "command" => ["/bin/sh", "-ec", script], **interactive}]}
    end

    def state?(stdout, expected)
      JSON.parse(stdout).dig("data", "state") == expected
    end

    def delete
      result = probe(%w[delete configmap k6-model --wait=true --timeout=20s]) { |out| out.include?('configmap "k6-model" deleted') }
      readback = command(%w[get configmap k6-model --ignore-not-found -o name])
      result.merge("passed" => result.fetch("passed") && successful?(readback) && readback.fetch("stdout").empty?)
    end

    def scale
      result = probe(%W[scale #{WEB} --replicas=2]) { |out| out.include?("scaled") }
      readback = command(%W[get #{WEB} -o json])
      persisted = successful?(readback) && JSON.parse(readback.fetch("stdout")).dig("spec", "replicas") == 2
      result.merge("passed" => result.fetch("passed") && persisted)
    end

    def top
      args = %w[top pods --no-headers]
      # The metrics API needs two samples before it reports CPU usage.
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 60
      loop do
        result = probe(args) { |out| out.match?(/^k6-web-\S+\s+\d+m?\s+\d+\w+/) }
        return result if result.fetch("passed") || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep 2
      end
    end

    def watch
      stream("watch", %w[get configmaps --watch -o name]) do |output|
        first = output.gets
        next false unless first&.start_with?("configmap/")

        created = command(%w[create configmap k6-watched --from-literal=observed=true])
        successful?(created) && output.each_line.any? { |line| line.strip == "configmap/k6-watched" }
      end
    end

    def port_forward
      stream("port-forward", %W[port-forward --address=127.0.0.1 #{WEB} :8080]) do |output|
        match = /Forwarding from 127\.0\.0\.1:(\d+) -> 8080/.match(output.gets.to_s)
        next false unless match

        response = Net::HTTP.start("127.0.0.1", Integer(match[1]), nil, open_timeout: 2, read_timeout: 5) { |client| client.get("/") }
        response.code == "200" && response.body.strip == HTTP_BODY
      end
    end

    def stream(verb, arguments)
      argv = Lanes.in_cluster_namespace(client_arguments(arguments))
      Open3.popen3(*argv, chdir: Lanes::ROOT, pgroup: true) do |stdin, stdout, stderr, process|
        stdin.close
        errors = Thread.new { stderr.read }
        passed = Timeout.timeout(30) { yield stdout }
        {"verb" => verb, "passed" => passed, "command" => argv,
         "reason" => ("expected stream data was not received" unless passed)}
      rescue Timeout::Error, SystemCallError, IOError => error
        {"verb" => verb, "passed" => false, "command" => argv, "reason" => error.message}
      ensure
        Lanes.terminate_group(process.pid) if process.alive?
        errors&.join(5)
      end
    end

    def probe(arguments, input: nil, expected_exit: 0, timeout: 35)
      result = command(arguments, input: input, timeout: timeout)
      output = result.fetch("stdout")
      passed = result.fetch("exit_status") == expected_exit && yield(output)
      {"verb" => arguments.first, "passed" => passed, "exit_status" => result["exit_status"],
       "command" => result["command"], "stdout_sha256" => Digest::SHA256.hexdigest(output),
       "reason" => (diagnostic(result) unless passed)}
    rescue JSON::ParserError, KeyError => error
      {"verb" => arguments.first, "passed" => false, "command" => result.fetch("command"), "reason" => error.message}
    end

    def command(arguments, input: nil, timeout: 35)
      Lanes.capture(client_arguments(arguments), timeout: timeout, stdin_data: input)
    end

    def client_arguments(arguments)
      [@binary, "--kubeconfig", @kubeconfig, "--namespace", @namespace, "--request-timeout=25s", *arguments]
    end

    def successful?(result)
      result.fetch("exit_status") == 0
    end

    def diagnostic(result)
      error = result.fetch("stderr").lines.last(3).join.strip
      error.empty? ? "unexpected command output" : error
    end
  end
end
