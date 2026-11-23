# frozen_string_literal: true

require "digest"

module Conformance
  module K6ClientEvidence
    SHA256 = /\A[0-9a-f]{64}\z/
    STREAMS = %w[watch port-forward].freeze
    INTERFACES = {"discovery" => true, "dynamic" => true, "typed" => true}.freeze

    module_function

    def check!(clients, matrix, kubeconfig: nil)
      kubectl = matrix.fetch("kubectl")
      go = matrix.fetch("client_go")
      tools = %w[helm kustomize].to_h { |name| [name, matrix.fetch(name)] }
      expected = kubectl.map { |pin| client_id("kubectl", pin) } + go.map { |pin| client_id("client-go", pin) }
      expected += tools.map { |name, pin| client_id(name, pin) }
      ids = clients.map { |row| row["id"] } if clients.is_a?(Array) && clients.all?(Hash)
      unless ids&.all?(String) && ids.sort == expected.sort && expected.uniq == expected
        raise ArgumentError, "K6 report does not contain the complete pinned client matrix"
      end

      by_id = clients.to_h { |row| [row.fetch("id"), row] }
      kubectl.each { |pin| check_kubectl!(by_id.fetch(client_id("kubectl", pin)), pin, kubeconfig) }
      go.each do |pin|
        result = by_id.fetch(client_id("client-go", pin))
        next if result["passed"] == true && result["module_sum"] == pin.fetch("sum") && SHA256.match?(result["probe_sha256"].to_s) &&
                result["interfaces"] == INTERFACES

        raise ArgumentError, "#{result.fetch("id")}: pinned module or discovery/dynamic/typed evidence is incomplete"
      end
      kubectl_path = kubectl.find { |pin| pin["version"] == matrix.fetch("target_api_server") }.fetch("path")
      tools.each { |name, pin| check_tool!(by_id.fetch(client_id(name, pin)), name, pin, kubectl_path, kubeconfig) }
    end

    def client_id(name, pin) = "#{name}-#{pin.fetch("version")}"

    def kubectl_operations(namespace)
      web = K6ClientVerbs::WEB
      attach = K6ClientVerbs::ATTACH
      {
        "api-resources" => %w[api-resources --no-headers],
        "explain" => %w[explain pod.spec],
        "get" => %W[get namespace #{namespace} -o json],
        "create" => %w[create configmap k6-model --from-literal=state=created -o json],
        "get object" => %w[get configmap k6-model -o json],
        "list" => %w[get configmaps -o json],
        "watch" => %w[get configmaps --watch -o name],
        "apply" => %w[apply -f - --server-side --field-manager=k6-client -o json],
        "diff" => %w[diff -f - --server-side --field-manager=k6-client],
        "patch" => %w[patch configmap k6-model --type=merge -p] + ['{"data":{"state":"patched"}}', "-o", "json"],
        "replace" => %w[replace -f - -o json],
        "delete" => %w[delete configmap k6-model --wait=true --timeout=20s],
        "auth" => %w[auth can-i get pods],
        "rollout" => %W[rollout status #{web} --timeout=100s],
        "wait" => %W[wait --for=condition=Ready #{attach} --timeout=100s],
        "logs" => %W[logs #{web}],
        "exec" => %W[exec #{web} -- /bin/busybox cat /tmp/k6-www/index.html],
        "attach" => %W[attach --stdin --quiet #{attach}],
        "port-forward" => %W[port-forward --address=127.0.0.1 #{web} :8080],
        "scale" => %W[scale #{web} --replicas=2],
        "top" => %w[top pods --no-headers]
      }
    end

    def check_kubectl!(row, pin, kubeconfig)
      id = row.fetch("id")
      namespace = row.fetch("namespace")
      setup = row.fetch("setup")
      kubeconfig ||= argv(setup)[2]
      prefix = fixture_prefix(kubeconfig, namespace, kubectl: true)
      path = pin.fetch("path")
      cleanup = row.fetch("cleanup")
      unless row["passed"] == true && row["image"] == K6ClientVerbs::IMAGE && row["sha256"] == pin.fetch("sha256") &&
             /\Ak6-client-[0-9a-f]{12}\z/.match?(namespace) && !kubeconfig.to_s.empty? &&
             setup["exit_status"] == 0 && command?(setup, path, prefix + %w[create -f -]) &&
             cleanup["exit_status"] == 0 && command?(cleanup, path, prefix + %W[delete namespace #{namespace} --ignore-not-found --wait=true --timeout=90s])
        raise ArgumentError, "#{id}: pinned executable or fixture setup and cleanup are incomplete"
      end

      expected = kubectl_operations(namespace)
      verbs = row.fetch("verbs")
      unless verbs.map { |verb| verb["verb"] }.sort == expected.keys.sort
        raise ArgumentError, "#{id}: report does not contain the complete kubectl operation inventory"
      end

      verbs.each do |probe|
        name = probe.fetch("verb")
        next if command?(probe, path, prefix + expected.fetch(name)) && outcome?(probe, expected_exit: name == "diff" ? 1 : 0, stream: STREAMS.include?(name))

        raise ArgumentError, "#{id}: missing or invalid kubectl #{name} execution"
      end
    end

    def tool_operations(name, kubeconfig, namespace, directory)
      kubectl = fixture_prefix(kubeconfig, namespace, kubectl: true)
      helm = fixture_prefix(kubeconfig, namespace)
      setup = ["kubectl", kubectl + %W[create namespace #{namespace}]]
      cleanup = ["kubectl", kubectl + %W[delete namespace #{namespace} --ignore-not-found --timeout=60s]]
      if name == "helm"
        readback = ["kubectl", kubectl + %w[get configmap k6-helm-fixture -o json]]
        [setup, [name, helm + %W[install fixture #{directory} --set state=installed]], readback,
         [name, helm + %W[upgrade fixture #{directory} --set state=upgraded]], readback, [name, helm + %w[rollback fixture 1]], readback,
         [name, helm + %w[uninstall fixture --wait]], ["kubectl", kubectl + %w[get configmap k6-helm-fixture --ignore-not-found -o name]], cleanup]
      else
        [setup, [name, %W[build #{directory}]], ["kubectl", kubectl + %w[apply -f -]],
         ["kubectl", kubectl + %w[get configmap k6-kustomize-fixture -o json]], cleanup]
      end
    end

    def check_tool!(row, name, pin, kubectl_path, kubeconfig)
      id = row.fetch("id")
      steps = row.fetch("steps")
      setup = argv(steps.fetch(0))
      namespace = setup[4]
      kubeconfig ||= setup[2]
      directory = argv(steps.fetch(1))[name == "helm" ? 7 : 2]
      expected = tool_operations(name, kubeconfig, namespace, directory)
      unless row["passed"] == true && row["sha256"] == pin.fetch("sha256") && /\Ak6-tool-[0-9a-f]{12}\z/.match?(namespace.to_s) &&
             !kubeconfig.to_s.empty? && !directory.to_s.empty? && steps.length == expected.length
        raise ArgumentError, "#{id}: pinned executable or tool step inventory is incomplete"
      end

      steps.zip(expected).each do |step, (tool, arguments)|
        path = tool == "kubectl" ? kubectl_path : pin.fetch("path")
        build = tool == "kustomize"
        next if command?(step, path, arguments) && outcome?(step, expected_exit: build ? nil : 0)

        verb_index = {"kustomize" => 0, "helm" => 4, "kubectl" => 5}.fetch(tool)
        raise ArgumentError, "#{id}: missing or invalid tool step #{arguments.fetch(verb_index)}"
      end
    end

    def fixture_prefix(kubeconfig, namespace, kubectl: false)
      flags = ["--kubeconfig", kubeconfig, "--namespace", namespace]
      flags << "--request-timeout=25s" if kubectl
      flags
    end

    def argv(record)
      command = record.fetch("command")
      raise ArgumentError, "invalid K6 client command record" unless command.is_a?(Array) && command.all? { |token| token.is_a?(String) && !token.empty? }

      command.take(3) == %w[ip netns exec] ? command.drop(4) : command
    end

    def command?(record, relative_path, arguments)
      executable, *recorded = argv(record)
      (executable == relative_path || executable.to_s.end_with?("/#{relative_path}")) && recorded == arguments
    end

    def outcome?(record, expected_exit:, stream: false)
      return false unless record["passed"] == true && record["reason"].nil?
      return record["exit_status"].nil? if stream

      record["exit_status"] == expected_exit && SHA256.match?(record["stdout_sha256"].to_s)
    end
  end
end
