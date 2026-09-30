# frozen_string_literal: true

require "digest"
require "fileutils"
require "securerandom"
require "timeout"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/runtime/native"
require "rubernetes/platform/linux/native_adapters"
require "rubernetes/platform/linux/mount"

# kubelet binds a container's subPaths when that container starts; an
# emptyDir path an init container wrote is bound after the sandbox exists.
# containerd sees such a bind because the host tree is shared and the
# container namespaces are its slaves.  Here the Pod root is a shared
# self-bind and the sandbox holder a slave of it, so a bind made under the
# Pod root after run_sandbox is what a later container mounts -- not the
# empty placeholder underneath it.
class NativeLateBindVisibilityTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux

  def test_a_bind_made_after_the_sandbox_exists_is_visible_to_a_container_started_later
    skip "needs root and a cgroup v2 root" unless Process.euid.zero? && File.writable?("/sys/fs/cgroup/cgroup.procs")

    Dir.mktmpdir("rubernetes-late-bind-") do |directory|
      lower = File.join(directory, "lower")
      FileUtils.mkdir_p(File.join(lower, "bin"))
      FileUtils.cp("/usr/bin/busybox", File.join(lower, "bin", "busybox"), preserve: true)
      pod_root = File.join(directory, "pods")
      FileUtils.mkdir_p(pod_root)
      mount = Linux::Mount.new
      mount.ensure_shared_self_bind(target: pod_root)
      # The volume exists before the sandbox (as a staged emptyDir does).
      volume = File.join(pod_root, "u1", "stages", "secrets")
      FileUtils.mkdir_p(volume)
      target = File.join(pod_root, "u1", "volume-subpaths", "app", "secrets", "0")
      FileUtils.mkdir_p(File.dirname(target))

      sandbox_root = File.join(directory, "sandboxes")
      runtime = Rubernetes::Runtime::Native.new(
        profile: :l3, l3: true,
        adapters: Linux::NativeAdapters.for_profile(profile: :l3, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup"),
        sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup", log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "journal.jsonl"),
        security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}
      )
      sandbox_id = "latebind-#{Process.pid}-#{SecureRandom.hex(4)}"
      sandbox = runtime.run_sandbox({"id" => sandbox_id, "image_bytes" => "img", "image_digest" => "sha256:#{Digest::SHA256.hexdigest("img")}",
                                     "lowerdirs" => [lower]}, request_id: sandbox_id)
      begin
        # "init container" writes the file, then the kubelet binds the subPath
        # on the host -- both after the sandbox's mount namespace was created.
        FileUtils.mkdir_p(File.join(volume, "rails-secrets"))
        File.write(File.join(volume, "rails-secrets", "secrets.yml"), "production: ok\n")
        File.write(target, "")
        mount.mount(source: File.join(volume, "rails-secrets", "secrets.yml"), target: target, filesystem: nil,
                    flags: Linux::Mount::MS_BIND, resource_id: "test:subpath-bind")
        begin
          container = runtime.create_container(sandbox, {"id" => "app", "rootfs_path" => lower,
                                                         "command" => ["/bin/busybox", "cat", "/srv/config/secrets.yml"],
                                                         "mounts" => [{"source" => target, "destination" => "/srv/config/secrets.yml",
                                                                       "readonly" => true, "propagation" => "None"}]})
          runtime.start_container(container)
          text = +""
          Timeout.timeout(15) { text = runtime.logs(container).to_s until text.include?("\n") || (sleep(0.1) && false) }

          assert_equal "production: ok", text.strip, "the container read the late subPath bind, not the empty placeholder"
        ensure
          begin
            mount.unmount(target: target, resource_id: "test:subpath-unbind")
          rescue StandardError
            nil
          end
        end
      ensure
        begin
          runtime.stop_sandbox(sandbox, timeout: 1) if runtime.sandboxes.any?
          runtime.remove_sandbox(sandbox) if runtime.sandboxes.any?
        rescue StandardError
          nil
        end
        system("umount", pod_root, err: File::NULL)
      end
    end
  end
end
