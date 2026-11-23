# frozen_string_literal: true

require "fileutils"
require "tmpdir"

require_relative "lanes"

module Conformance
  class K6ToolClients
    GO_PROBE = File.join(Lanes::ROOT, "test/compatibility/clients/client_go_probe.go")
    KUBECTL = File.join(Lanes::ROOT, "build/tools/kubectl-v1.36.2")

    def initialize(matrix, kubeconfig)
      @matrix = matrix
      @kubeconfig = kubeconfig
    end

    def run
      results = @matrix.fetch("client_go").map { |entry| client_go(entry) }
      results << pinned_binary("helm") { |binary, directory, namespace| helm(binary, directory, namespace) }
      results << pinned_binary("kustomize") { |binary, directory, namespace| kustomize(binary, directory, namespace) }
      results
    end

    private

    def client_go(entry)
      version = entry.fetch("version")
      id = "client-go-#{version}"
      Dir.mktmpdir("k6-client-go") do |directory|
        FileUtils.cp(GO_PROBE, File.join(directory, "main.go"))
        File.write(File.join(directory, "go.mod"), "module rubernetes.dev/k6-probe\n\ngo 1.26.0\n\nrequire k8s.io/client-go #{version}\n")
        env = {"GOWORK" => "off"}
        download = Lanes.capture(["go", "mod", "download", "-json", "k8s.io/client-go@#{version}"], env: env, chdir: directory, timeout: 120)
        return failed(id, download) unless succeeded?(download)

        module_info = JSON.parse(download.fetch("stdout"))
        unless module_info.values_at("Sum", "GoModSum") == entry.values_at("sum", "go_mod_sum")
          return {"id" => id, "passed" => false, "reason" => "client-go module checksum mismatch"}
        end

        binary = File.join(directory, "client-go-probe")
        build = Lanes.capture(["go", "build", "-mod=mod", "-o", binary, "."], env: env, chdir: directory, timeout: 240)
        return failed(id, build) unless succeeded?(build)

        execution = Lanes.capture([binary, @kubeconfig, test_namespace], timeout: 130)
        return failed(id, execution) unless succeeded?(execution)

        result = JSON.parse(execution.fetch("stdout"))
        {"id" => id, "passed" => %w[typed dynamic discovery].all? { |client| result[client] == true },
         "probe_sha256" => Digest::SHA256.file(binary).hexdigest, "module_sum" => module_info.fetch("Sum"),
         "interfaces" => result}
      end
    rescue Errno::ENOENT, JSON::ParserError => error
      {"id" => id, "passed" => false, "reason" => error.message}
    end

    def pinned_binary(name)
      entry = @matrix.fetch(name)
      id = "#{name}-#{entry.fetch("version")}"
      binary = File.join(Lanes::ROOT, entry.fetch("path"))
      unless File.executable?(binary) && Digest::SHA256.file(binary).hexdigest == entry.fetch("sha256")
        return {"id" => id, "passed" => false, "reason" => "pinned executable #{entry.fetch("path")} is absent or has the wrong checksum"}
      end

      namespace = test_namespace
      Dir.mktmpdir("k6-#{name}") do |directory|
        begin
          steps = [command(kubectl("create", "namespace", namespace, namespace: namespace))]
          steps.concat(yield(binary, directory, namespace)) if steps.all? { |step| step.fetch("passed") }
        ensure
          cleanup = kubectl("delete", "namespace", namespace, "--ignore-not-found", "--timeout=60s", namespace: namespace)
          steps << command(cleanup, timeout: 70)
        end
        {"id" => id, "passed" => steps.all? { |step| step.fetch("passed") }, "sha256" => entry.fetch("sha256"), "steps" => steps}
      end
    end

    def helm(binary, directory, namespace)
      FileUtils.mkdir_p(File.join(directory, "templates"))
      File.write(File.join(directory, "Chart.yaml"), "apiVersion: v2\nname: client-fixture\nversion: 0.1.0\n")
      File.write(File.join(directory, "templates", "configmap.yaml"), <<~YAML)
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: k6-helm-fixture
        data:
          state: {{ .Values.state | quote }}
      YAML
      helm = [binary, "--kubeconfig", @kubeconfig, "--namespace", namespace]
      [
        command([*helm, "install", "fixture", directory, "--set", "state=installed"]),
        expect_configmap(namespace, "k6-helm-fixture", "installed"),
        command([*helm, "upgrade", "fixture", directory, "--set", "state=upgraded"]),
        expect_configmap(namespace, "k6-helm-fixture", "upgraded"),
        command([*helm, "rollback", "fixture", "1"]),
        expect_configmap(namespace, "k6-helm-fixture", "installed"),
        command([*helm, "uninstall", "fixture", "--wait"]),
        command(kubectl("get", "configmap", "k6-helm-fixture", "--ignore-not-found", "-o", "name", namespace: namespace), &:empty?)
      ]
    end

    def kustomize(binary, directory, namespace)
      File.write(File.join(directory, "kustomization.yaml"), <<~YAML)
        apiVersion: kustomize.config.k8s.io/v1beta1
        kind: Kustomization
        resources:
        - configmap.yaml
        namePrefix: k6-
      YAML
      File.write(File.join(directory, "configmap.yaml"), <<~YAML)
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: kustomize-fixture
        data:
          state: customized
      YAML
      command_line = [binary, "build", directory]
      built = Lanes.capture(command_line, timeout: 30)
      return [failed("kustomize build", built)] unless succeeded?(built)

      [
        {"command" => command_line, "passed" => true, "stdout_sha256" => Digest::SHA256.hexdigest(built.fetch("stdout"))},
        command(kubectl("apply", "-f", "-", namespace: namespace), input: built.fetch("stdout")),
        expect_configmap(namespace, "k6-kustomize-fixture", "customized")
      ]
    end

    def expect_configmap(namespace, name, expected)
      command(kubectl("get", "configmap", name, "-o", "json", namespace: namespace)) do |output|
        JSON.parse(output).dig("data", "state") == expected
      end
    end

    def test_namespace
      "k6-tool-#{SecureRandom.hex(6)}"
    end

    def kubectl(*arguments, namespace:)
      [KUBECTL, "--kubeconfig", @kubeconfig, "--namespace", namespace, "--request-timeout=25s", *arguments]
    end

    def command(argv, input: nil, timeout: 45)
      result = Lanes.capture(argv, timeout: timeout, stdin_data: input)
      passed = succeeded?(result) && (!block_given? || yield(result.fetch("stdout")))
      {"command" => argv, "passed" => passed, "exit_status" => result.fetch("exit_status"),
       "stdout_sha256" => Digest::SHA256.hexdigest(result.fetch("stdout")),
       "stderr" => (result.fetch("stderr").lines.last(4).join.strip unless passed)}
    rescue JSON::ParserError => error
      {"command" => argv, "passed" => false, "reason" => error.message}
    end

    def succeeded?(result)
      result.fetch("exit_status") == 0
    end

    def failed(id, result)
      {"id" => id, "passed" => false, "command" => result.fetch("command"), "exit_status" => result.fetch("exit_status"),
       "stderr" => result.fetch("stderr").lines.last(8).join.strip}
    end
  end
end
