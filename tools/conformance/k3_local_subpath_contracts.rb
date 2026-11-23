# frozen_string_literal: true

module Conformance
  # Public subPath observations in upstream storage/testsuites/subpath.go.
  module K3LocalSubpathContracts
    D = K7ClusterDriver
    VOLUME = "/test-volume"
    FILE = "test-file"
    CONTENT = "mount-tester new file"
    PROBE = "/probe-volume/probe-file"
    AGNHOST = "registry.k8s.io/e2e-test-images/agnhost:2.63.0"
    SHELL = ["/bin/sh", "-ec"].freeze
    OUTSIDE_LINKS = {
      "subpath-directory-outside" => "/bin",
      "subpath-file-outside" => "/bin/sh",
      "subpath-missing-outside" => "/bin/notanexistingpath",
      "subpath-backstep-outside" => "../"
    }.freeze

    private

    def verify_subpath(key, namespace, claim)
      return subpath_rejected(namespace, claim, OUTSIDE_LINKS.fetch(key)) if OUTSIDE_LINKS.key?(key)

      case key
      when "subpath-missing", "subpath-existing-directory"
        subpath_write_through(namespace, claim, create_first: key == "subpath-existing-directory")
      when "subpath-existing-single-file", "subpath-readonly-directory"
        subpath_file_in_directory(namespace, claim, readonly: key == "subpath-readonly-directory")
      when "subpath-single-file", "subpath-readonly-file"
        subpath_file(namespace, claim, readonly: key == "subpath-readonly-file")
      when "subpath-multiple" then subpath_multiple(namespace, claim)
      when "subpath-readonly-source" then subpath_readonly_source(namespace, claim)
      when "subpath-refuse-write" then subpath_refuse_write(namespace, claim)
      when "subpath-removed-directory" then subpath_removed_directory(namespace, claim)
      when "subpath-restart-file", "subpath-restart-directory"
        subpath_restart(namespace, claim, file: key == "subpath-restart-file")
      else raise ArgumentError, "unknown subPath contract #{key.inspect}"
      end
    end

    def subpath_write_through(namespace, claim, create_first:)
      init = []
      init << prepare("mkdir -p #{VOLUME}/#{namespace}") if create_first
      init << mount_test("write", "--new_file_0644=#{VOLUME}/#{FILE}", mount: subpath_mount(namespace))
      read = reader("#{VOLUME}/#{namespace}/#{FILE}", mount: full_mount)
      read_subpath_pod(namespace, claim, read, init: init)
    end

    def subpath_file_in_directory(namespace, claim, readonly:)
      init = [prepare("mkdir -p #{VOLUME}/#{namespace}; printf '%s\\n' '#{CONTENT}' > #{VOLUME}/#{namespace}/#{FILE}")]
      read = reader("#{VOLUME}/#{FILE}", mount: subpath_mount(namespace, readonly: readonly))
      read_subpath_pod(namespace, claim, read, init: init)
    end

    def subpath_file(namespace, claim, readonly:)
      content = readonly ? CONTENT : namespace
      init = [prepare("printf '%s\\n' '#{content}' > #{VOLUME}/#{namespace}")]
      read = reader(VOLUME, mount: subpath_mount(namespace, readonly: readonly))
      read_subpath_pod(namespace, claim, read, init: init, content: content)
    end

    def subpath_rejected(namespace, claim, link)
      init = [prepare("test -L #{VOLUME}/#{namespace} || ln -s '#{link}' #{VOLUME}/#{namespace}")]
      read = reader("#{VOLUME}/#{FILE}", mount: subpath_mount(namespace))
      create(subject(namespace, claim, "rejected-subpath", [read], init: init))
      waiting = nil
      D.wait_until("CreateContainerConfigError referencing the rejected subPath", 45) do
        status = subpath_status(namespace, "rejected-subpath", read.fetch("name"))
        waiting = status.dig("state", "waiting")
        raise "the rejected subPath container unexpectedly started" if status.dig("state", "running") || status.dig("state", "terminated")

        waiting && waiting["reason"] == "CreateContainerConfigError" && waiting["message"].to_s.include?("subPath")
      end
      waiting
    end

    def subpath_multiple(namespace, claim)
      paths = ["/test-subpath1/#{FILE}", "/test-subpath2/#{FILE}"]
      init = [prepare("mkdir -p #{VOLUME}/subpath1 #{VOLUME}/subpath2")]
      write = mount_test("write-multiple", "--new_file_0644=#{paths.first}", "--new_file_0666=#{paths.last}", mount: subpath_mount(namespace))
      write["volumeMounts"] << subpath_mount("subpath1", path: "/test-subpath1") << subpath_mount("subpath2", path: "/test-subpath2")
      logs = completed_pod(subject(namespace, claim, "multiple-subpaths", [write], init: init))
      paths.each { |path| assert_mounttest_content(logs, path, CONTENT) }
      {"written_and_read" => paths, "logs" => logs}
    end

    def subpath_readonly_source(namespace, claim)
      init = [prepare("mkdir -p #{VOLUME}/#{namespace}"),
              mount_test("write", "--new_file_0644=#{VOLUME}/#{FILE}", mount: subpath_mount(namespace))]
      read = reader("#{VOLUME}/#{FILE}", mount: subpath_mount(namespace))
      writable = read_subpath_pod(namespace, claim, read, init: init)
      readonly = read_subpath_pod(namespace, claim, read, source_readonly: true)
      {"writable" => writable, "read_only_source" => readonly}
    end

    def subpath_refuse_write(namespace, claim)
      format = subpath_container("format", [*SHELL, "echo nothing"], full_mount)
      completed_pod(subject(namespace, claim, "format-volume", [format]))
      write = mount_test("write", "--new_file_0644=#{VOLUME}/#{namespace}", mount: subpath_mount(namespace))
      create(subject(namespace, claim, "write-attempt", [write], source_readonly: true))
      failure = nil
      D.wait_until("a subPath configuration error or a failed write", 45) do
        state = subpath_status(namespace, "write-attempt", "write").fetch("state", {})
        terminated = state["terminated"]
        waiting = state["waiting"]
        if terminated
          raise "write to read-only subPath succeeded" if terminated["exitCode"] == 0

          failure = terminated
        elsif waiting && waiting["reason"] == "CreateContainerConfigError" && waiting["message"].to_s.include?("subPath")
          failure = waiting
        end
      end
      failure
    end

    def subpath_removed_directory(namespace, claim)
      object = running_subpath(namespace, claim, "removed-subpath")
      pod_uid = object.dig("metadata", "uid")
      node = object.dig("spec", "nodeName")
      root = pod_volume_root(node, pod_uid)
      subpaths = mounts_below(root).grep(%r{/volume-subpaths/})
      raise "no mounted subPath before directory removal" if subpaths.empty?

      exec_in(namespace, "removed-subpath", "volume", "rm", "-r", "#{VOLUME}/#{namespace}")
      delete_pod(namespace, "removed-subpath")
      D.wait_until("unmount after removing the subPath directory", self.class::TIMEOUT) { mounts_below(root).empty? }
      {"pod_uid" => pod_uid, "unmounted_subpaths" => subpaths}
    end

    def subpath_restart(namespace, claim, file:)
      pod_name = "subpath-restart"
      action = file ? "touch" : "mkdir -p"
      init = [prepare("#{action} #{VOLUME}/#{namespace}; touch #{PROBE}")]
      observed = subpath_container("subpath", self.class::IDLE, subpath_mount(namespace))
      observed["livenessProbe"] = {"exec" => {"command" => ["cat", PROBE]}, "initialDelaySeconds" => 1, "periodSeconds" => 2,
                                   "failureThreshold" => 1}
      create(subject(namespace, claim, pod_name, [observed, subpath_container("volume", self.class::IDLE, full_mount)],
                     init: init, restart_policy: "OnFailure"))
      await_ready(namespace, pod_name)
      exec_in(namespace, pod_name, "volume", "rm", PROBE)
      D.wait_until("liveness probe restart with a mounted subPath", 90) { restart_count(namespace, pod_name).positive? }
      exec_in(namespace, pod_name, "volume", *SHELL, "echo test-after > #{PROBE}")
      await_ready(namespace, pod_name)
      check_path = file ? "-f" : "-d"
      exec_in(namespace, pod_name, "subpath", *SHELL, "test #{check_path} #{VOLUME}")
      restarts = stable_restarts(namespace, pod_name)
      {"restarts" => restarts, "stable_seconds" => 60, "mount_type" => (file ? "file" : "directory")}
    end

    def stable_restarts(namespace, pod_name)
      previous = nil
      stable_since = nil
      D.wait_until("the subPath restart count to stabilize for a minute", 15 * 60) do
        count = restart_count(namespace, pod_name)
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        stable_since = now if count != previous
        previous = count
        count.positive? && now - stable_since >= 60
      end
      previous
    end

    def restart_count(namespace, name) = subpath_status(namespace, name, "subpath").fetch("restartCount", 0)

    def running_subpath(namespace, claim, name, grace_period: 1)
      containers = [subpath_container("subpath", self.class::IDLE, subpath_mount(namespace)),
                    subpath_container("volume", self.class::IDLE, full_mount)]
      object = subject(namespace, claim, name, containers)
      object["spec"]["terminationGracePeriodSeconds"] = grace_period
      create(object)
      await_ready(namespace, name)
      D.kubectl_object("-n", namespace, "get", "pod", name)
    end

    def subpath_status(namespace, pod_name, container)
      object = D.kubectl_object("-n", namespace, "get", "pod", pod_name)
      Array(object&.dig("status", "containerStatuses")).find { |entry| entry["name"] == container } || {}
    end

    def await_ready(namespace, pod_name)
      kubectl!("-n", namespace, "wait", "--for=condition=Ready", "pod/#{pod_name}", "--timeout=#{self.class::TIMEOUT}s")
    end

    def read_subpath_pod(namespace, claim, container, init: [], source_readonly: false, content: CONTENT)
      path = container.fetch("command").find { |argument| argument.start_with?("--file_content_in_loop=") }.split("=", 2).last
      logs = completed_pod(subject(namespace, claim, "read-subpath", [container], init: init, source_readonly: source_readonly))
      assert_mounttest_content(logs, path, content)
      {"path" => path, "content" => content}
    end

    def assert_mounttest_content(logs, path, content)
      raise "unexpected content at #{path}: #{logs}" unless logs.include?("content of file \"#{path}\": #{content}")
    end

    def completed_pod(object)
      namespace, name = object.fetch("metadata").values_at("namespace", "name")
      create(object)
      await(namespace, "pod", name, %w[status phase], "Succeeded")
      kubectl!("-n", namespace, "logs", name, "-c", object.dig("spec", "containers", 0, "name"))
    ensure
      delete_pod(namespace, name) if namespace && name
    end

    def delete_pod(namespace, name)
      kubectl!("-n", namespace, "delete", "pod", name, "--ignore-not-found", "--wait=true", "--timeout=#{self.class::TIMEOUT}s")
    end

    def reader(path, mount:)
      mount_test("read", "--file_content_in_loop=#{path}", "--retry_time=20", mount: mount)
    end

    def mount_test(name, *arguments, mount:)
      subpath_container(name, ["/agnhost", "mounttest", *arguments], mount, image: AGNHOST)
    end

    def full_mount = {"name" => "data", "mountPath" => VOLUME}

    def subpath_mount(name, readonly: false, path: VOLUME)
      full_mount.merge("mountPath" => path, "subPath" => name, "readOnly" => readonly)
    end

    def prepare(command) = subpath_container("prepare", [*SHELL, command], full_mount)

    def subpath_container(name, command, mount, image: self.class::BUSYBOX)
      {"name" => name, "image" => image, "command" => command, "securityContext" => {"privileged" => true},
       "volumeMounts" => [mount, {"name" => "probe-volume", "mountPath" => File.dirname(PROBE)}]}
    end

    def subject(namespace, claim, name, containers, init: [], source_readonly: false, restart_policy: "Never")
      object = pod(namespace, claim, name, containers.first)
      spec = object.fetch("spec")
      spec["containers"] = containers
      spec["initContainers"] = init
      spec["terminationGracePeriodSeconds"] = 1
      spec["restartPolicy"] = restart_policy
      spec.dig("volumes", 0, "persistentVolumeClaim")["readOnly"] = true if source_readonly
      spec["volumes"] << {"name" => "probe-volume", "emptyDir" => {}}
      object
    end
  end
end
