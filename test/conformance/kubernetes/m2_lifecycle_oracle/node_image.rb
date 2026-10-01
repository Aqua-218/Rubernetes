#!/usr/bin/env ruby
# frozen_string_literal: true

# Self-contained Kubernetes v1.36.2 node image for the M2 lifecycle oracle.
#
# Runner mode (default; stdin JSON from runner.rb, stdout JSON):
#   verifies that the digest-pinned node image recorded in
#   third_party/locks/m2-lifecycle-node-image.json is present in the local
#   Docker image store, copies containerd and runc out of that exact image into
#   build/tools so their bytes can be hashed on the host, and reports the image
#   plus runtime identities. It never builds or writes locks in this mode.
#
# Lock mode (`--write-lock`, operator action):
#   builds the node image from the pinned Kubernetes source checkout with the
#   locked kind release (`kind build node-image`), pushes it through an
#   ephemeral local registry to obtain a content digest that Docker can resolve
#   offline, records every build input, and writes
#   third_party/locks/m2-lifecycle-node-image.json and
#   third_party/locks/m2-lifecycle-cni.json. `--reuse-existing-image` accepts an
#   already built `rubernetes/kind-node:v1.36.2` instead of rebuilding.

require "digest"
require "fileutils"
require "json"
require "net/http"
require "open3"
require "rbconfig"
require "shellwords"
require "socket"
require "time"
require "tmpdir"
require "uri"

module M2LifecycleOracleNodeImage
  class BuildError < StandardError; end

  ROOT = File.expand_path("../../../..", __dir__).freeze
  KIND_LOCK_RELATIVE_PATH = "third_party/locks/kind-v0.33.0.json"
  KIND_LOCK_PATH = File.join(ROOT, KIND_LOCK_RELATIVE_PATH).freeze
  NODE_IMAGE_LOCK_RELATIVE_PATH = "third_party/locks/m2-lifecycle-node-image.json"
  NODE_IMAGE_LOCK_PATH = File.join(ROOT, NODE_IMAGE_LOCK_RELATIVE_PATH).freeze
  CNI_LOCK_RELATIVE_PATH = "third_party/locks/m2-lifecycle-cni.json"
  CNI_LOCK_PATH = File.join(ROOT, CNI_LOCK_RELATIVE_PATH).freeze
  KUBERNETES_LOCK_PATH = File.join(ROOT, "third_party/locks/kubernetes-v1.36.2.json").freeze
  EXTRACT_ROOT = File.join(ROOT, "build/tools/m2-lifecycle-oracle/node-image").freeze
  LOCAL_TAG = "rubernetes/kind-node:v1.36.2"
  KUBERNETES_VERSION = "v1.36.2"
  KUBERNETES_SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
  SOURCE_ENV = "RUBERNETES_M2_KUBERNETES_SOURCE"
  REGISTRY_IMAGE = "docker.io/library/registry:3"
  # Ephemeral registry / API server ports stay above 20000 so the host k3s
  # cluster on 6443 and other services are never touched.
  PORT_RANGE = (25_000..25_999)
  API_SERVER_PORT = 26_443
  RUNTIME_BINARIES = {
    "containerd" => "/usr/local/bin/containerd",
    "runc" => "/usr/local/sbin/runc",
    "kubelet" => "/usr/bin/kubelet"
  }.freeze
  CNI_PLUGIN_BINARIES = %w[host-local loopback portmap ptp].freeze
  CNI_CONFIG_PATH = "/etc/cni/net.d/10-kindnet.conflist"
  KIND_REPOSITORY = "https://github.com/kubernetes-sigs/kind.git"
  BUILD_TIMEOUT_SECONDS = 2700

  module_function

  def canonical_digest(value, excluded_keys: [])
    Digest::SHA256.hexdigest(JSON.generate(canonical_value(value, excluded_keys.map(&:to_s))))
  end

  def canonical_value(value, excluded = [])
    case value
    when Hash then value.keys.map(&:to_s).reject do |key|
      excluded.include?(key)
    end.sort.to_h { |key| [key, canonical_value(value[key] || value[key.to_sym])] }
    when Array then value.map { |child| canonical_value(child) }
    else value
    end
  end

  def parse_json(path)
    JSON.parse(File.binread(path), max_nesting: 128)
  rescue Errno::ENOENT => error
    raise BuildError, "required input is missing: #{path}: #{error.message}"
  rescue JSON::ParserError => error
    raise BuildError, "required input is invalid JSON: #{path}: #{error.message}"
  end

  def run(*command, stdin_data: nil, env: {}, timeout: 600, allow_failure: false)
    words = ["timeout", "--kill-after=15", timeout.to_s, *command.map(&:to_s)]
    stdout, stderr, status = Open3.capture3(env, *words, stdin_data: stdin_data, chdir: ROOT)
    unless status.success? || allow_failure
      detail = stderr.to_s.strip.empty? ? stdout.to_s.strip : stderr.to_s.strip
      raise BuildError, "command failed (#{status.exitstatus.inspect}): #{command.map(&:to_s).shelljoin}: #{detail[-3000..] || detail}"
    end
    [stdout, stderr, status]
  end

  def docker(*, **)
    run("docker", *, **)
  end

  def kind_lock
    lock = parse_json(KIND_LOCK_PATH)
    raise BuildError, "kind lock schema_version must be 1" unless lock["schema_version"] == 1
    raise BuildError, "kind lock digest does not match content" unless lock["lock_sha256"] == canonical_digest(lock,
                                                                                                               excluded_keys: ["lock_sha256"])

    lock
  end

  # Returns the verified kind binary path, downloading the locked release only
  # when the file is absent. The checksum is always re-verified.
  def ensure_kind!(lock)
    path = File.join(ROOT, lock.fetch("install_path"))
    artifact = lock.fetch("artifacts").fetch("linux/amd64")
    unless File.file?(path)
      FileUtils.mkdir_p(File.dirname(path))
      run("curl", "-fsSL", "-o", "#{path}.download", artifact.fetch("url"), timeout: 600)
      File.rename("#{path}.download", path)
      File.chmod(0o755, path)
    end
    actual = Digest::SHA256.file(path).hexdigest
    unless actual == artifact.fetch("sha256")
      raise BuildError,
            "kind binary #{path} SHA-256 #{actual} does not match lock #{artifact.fetch("sha256")}"
    end

    version, = run(path, "version")
    unless version.strip == lock.fetch("version_output")
      raise BuildError,
            "kind binary reports #{version.strip.inspect}, lock expects #{lock.fetch("version_output").inspect}"
    end

    path
  end

  def verify_source_checkout!(source_root)
    if source_root.to_s.empty? || !File.directory?(source_root)
      raise BuildError,
            "#{SOURCE_ENV} must point to the pinned Kubernetes source checkout"
    end

    head, = run("git", "-C", source_root, "rev-parse", "HEAD")
    unless head.strip == KUBERNETES_SOURCE_COMMIT
      raise BuildError,
            "Kubernetes source checkout is at #{head.strip}, expected #{KUBERNETES_SOURCE_COMMIT}"
    end

    tag, = run("git", "-C", source_root, "describe", "--tags", "--exact-match", "HEAD")
    unless tag.strip == KUBERNETES_VERSION
      raise BuildError,
            "Kubernetes source checkout is tagged #{tag.strip}, expected #{KUBERNETES_VERSION}"
    end

    dirty, = run("git", "-C", source_root, "status", "--porcelain", "--untracked-files=no")
    raise BuildError, "Kubernetes source checkout has tracked modifications" unless dirty.strip.empty?

    true
  end

  def free_port
    PORT_RANGE.each do |port|
      server = TCPServer.new("127.0.0.1", port)
      server.close
      return port
    rescue Errno::EADDRINUSE, Errno::EACCES
      next
    end
    raise BuildError, "no free port in #{PORT_RANGE}"
  end

  def image_id(reference)
    stdout, = docker("image", "inspect", "--format", "{{.Id}}", reference)
    stdout.strip
  end

  def repo_digests(reference)
    stdout, = docker("image", "inspect", "--format", "{{json .RepoDigests}}", reference)
    JSON.parse(stdout)
  end

  # Pushes the local image through an ephemeral registry so Docker records a
  # content digest under a name it can resolve offline afterwards.
  def pin_by_digest!(local_tag)
    registry_id = image_id(REGISTRY_IMAGE)
    registry_digest = repo_digests(REGISTRY_IMAGE).find { |entry| entry.start_with?("registry@sha256:") }
    raise BuildError, "registry image digest is unavailable" unless registry_digest

    port = free_port
    name = "rubernetes-m2-node-image-registry-#{Process.pid}"
    docker("run", "-d", "--rm", "--name", name, "-p", "127.0.0.1:#{port}:5000", "docker.io/library/#{registry_digest}")
    begin
      target = "localhost:#{port}/rubernetes/kind-node:#{KUBERNETES_VERSION}"
      docker("tag", local_tag, target)
      attempts = 0
      loop do
        attempts += 1
        _stdout, stderr, status = docker("push", "-q", target, timeout: 900, allow_failure: true)
        break if status.success?
        raise BuildError, "docker push to the ephemeral registry failed after #{attempts} attempts: #{stderr.strip}" if attempts >= 5

        sleep(2)
      end
      digest_reference = repo_digests(target).find { |entry| entry.start_with?("localhost:#{port}/rubernetes/kind-node@sha256:") }
      raise BuildError, "docker did not record a repo digest for #{target}" unless digest_reference

      # The pushed tag must stay: `docker rmi <tag>` would also drop the digest
      # reference from the local store.
      {"reference" => digest_reference,
       "registry_image" => {"reference" => REGISTRY_IMAGE, "digest_reference" => "docker.io/library/#{registry_digest}",
                            "image_id" => registry_id}}
    ensure
      docker("rm", "-f", name, allow_failure: true)
    end
  end

  # Inspect the node image with containerd running so image digests and binary
  # identities come from the image itself.
  def inspect_node_image(reference)
    script = <<~'SH'
      set -eu
      containerd >/tmp/containerd.log 2>&1 &
      for _ in $(seq 1 50); do ctr version >/dev/null 2>&1 && break; sleep 0.2; done
      echo "@@versions"
      /usr/local/bin/containerd --version
      /usr/local/sbin/runc --version | head -1
      /usr/bin/kubelet --version
      echo "@@sha"
      sha256sum /usr/local/bin/containerd /usr/local/sbin/runc /usr/bin/kubelet /opt/cni/bin/host-local /opt/cni/bin/loopback /opt/cni/bin/portmap /opt/cni/bin/ptp /kind/manifests/default-cni.yaml
      echo "@@images"
      ctr -n k8s.io images ls | awk 'NR>1 {print $1, $3}'
      for ref in $(grep -E '^\s+image:' /kind/manifests/default-cni.yaml | awk '{print $2}') registry.k8s.io/kube-apiserver:v1.36.2 $(ctr -n k8s.io images ls -q | grep '^registry.k8s.io/etcd:'); do
        echo "@@cri-inspect:$ref"
        crictl --runtime-endpoint unix:///run/containerd/containerd.sock inspecti "$ref"
      done
      echo "@@cni-manifest-image"
      grep -E '^\s+image:' /kind/manifests/default-cni.yaml | awk '{print $2}'
      echo "@@os"
      . /etc/os-release && echo "$PRETTY_NAME"
      echo "@@kind-version"
      cat /kind/version
    SH
    stdout, = docker("run", "--rm", "--privileged", "--entrypoint", "bash", reference, "-c", script, timeout: 300)
    sections = {}
    current = nil
    stdout.each_line do |line|
      if line.start_with?("@@")
        current = line.strip.delete_prefix("@@")
        sections[current] = []
      elsif current
        sections[current] << line.rstrip
      end
    end
    versions = sections.fetch("versions")
    shas = sections.fetch("sha").to_h { |line| line.split(/\s+/, 2).reverse }
    images = sections.fetch("images").reject do |line|
      line.start_with?("sha256:", "import-")
    end.to_h { |line| line.split(" ", 2) }
    image_ref = lambda do |name_prefix|
      entry = images.find { |name, _| name.start_with?(name_prefix) }
      raise BuildError, "node image does not contain #{name_prefix}" unless entry

      name, digest = entry
      "#{name.split(":").first}@#{digest}"
    end
    kindnetd_tag = sections.fetch("cni-manifest-image").first.to_s.strip
    raise BuildError, "default CNI manifest image is missing" if kindnetd_tag.empty?

    kindnetd_digest = images.fetch(kindnetd_tag) { raise BuildError, "kindnetd image #{kindnetd_tag} is not in the node image store" }
    cri_ids = sections.select { |name, _| name.start_with?("cri-inspect:") }.to_h do |name, lines|
      ref = name.delete_prefix("cri-inspect:")
      id = begin
        JSON.parse(lines.join("\n"), max_nesting: 64).dig("status", "id")
      rescue JSON::ParserError => error
        raise BuildError, "crictl inspecti #{ref} returned invalid JSON: #{error.message}"
      end
      raise BuildError, "CRI image ID for #{ref} is unavailable" unless id.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)

      [ref, id]
    end
    etcd_tag = cri_ids.keys.find { |ref| ref.start_with?("registry.k8s.io/etcd:") }
    {
      "runtime" => {
        "containerd" => {"in_image_path" => "/usr/local/bin/containerd", "version" => versions.fetch(0),
                         "binary_sha256" => shas.fetch("/usr/local/bin/containerd")},
        "runc" => {"in_image_path" => "/usr/local/sbin/runc", "version" => versions.fetch(1),
                   "binary_sha256" => shas.fetch("/usr/local/sbin/runc")},
        "kubelet" => {"in_image_path" => "/usr/bin/kubelet", "version" => versions.fetch(2),
                      "binary_sha256" => shas.fetch("/usr/bin/kubelet")}
      },
      "images" => {
        "kube_apiserver" => image_ref.call("registry.k8s.io/kube-apiserver:"),
        "kube_controller_manager" => image_ref.call("registry.k8s.io/kube-controller-manager:"),
        "kube_scheduler" => image_ref.call("registry.k8s.io/kube-scheduler:"),
        "kube_proxy" => image_ref.call("registry.k8s.io/kube-proxy:"),
        "etcd" => image_ref.call("registry.k8s.io/etcd:"),
        "coredns" => image_ref.call("registry.k8s.io/coredns/coredns:"),
        "pause" => image_ref.call("registry.k8s.io/pause:"),
        "kindnetd" => "#{kindnetd_tag.split(":").first}@#{kindnetd_digest}"
      },
      "kindnetd" => {"tag" => kindnetd_tag, "version" => kindnetd_tag.split(":").last, "digest" => kindnetd_digest,
                     "cri_image_id" => cri_ids.fetch(kindnetd_tag)},
      "cri_image_ids" => {
        "kube_apiserver" => {"tag" => "registry.k8s.io/kube-apiserver:v1.36.2",
                             "id" => cri_ids.fetch("registry.k8s.io/kube-apiserver:v1.36.2")},
        "etcd" => {"tag" => etcd_tag, "id" => cri_ids.fetch(etcd_tag)},
        "kindnetd" => {"tag" => kindnetd_tag, "id" => cri_ids.fetch(kindnetd_tag)}
      },
      "cni_plugin_binaries" => CNI_PLUGIN_BINARIES.to_h { |name| [name, shas.fetch("/opt/cni/bin/#{name}")] },
      "cni_manifest_sha256" => shas.fetch("/kind/manifests/default-cni.yaml"),
      "os_image" => sections.fetch("os").first.to_s.strip,
      "kind_version_file" => sections.fetch("kind-version").first.to_s.strip
    }
  end

  # Copy containerd and runc out of the exact image so their bytes can be hashed
  # on the host; returns runtime identities in the runner's shape.
  def extract_runtime!(reference, image_id_value, lock_runtime)
    directory = File.join(EXTRACT_ROOT, image_id_value.delete_prefix("sha256:"))
    FileUtils.mkdir_p(directory)
    container = nil
    runtime = {}
    %w[containerd runc].each do |name|
      in_image_path = lock_runtime.fetch(name).fetch("in_image_path")
      host_path = File.join(directory, name)
      unless File.file?(host_path) && Digest::SHA256.file(host_path).hexdigest == lock_runtime.fetch(name).fetch("binary_sha256")
        container ||= docker("create", reference).first.strip
        docker("cp", "#{container}:#{in_image_path}", "#{host_path}.tmp")
        File.rename("#{host_path}.tmp", host_path)
        File.chmod(0o755, host_path)
      end
      real_path = File.realpath(host_path)
      sha = Digest::SHA256.file(real_path).hexdigest
      unless sha == lock_runtime.fetch(name).fetch("binary_sha256")
        raise BuildError,
              "extracted #{name} SHA-256 #{sha} does not match the node image lock #{lock_runtime.fetch(name).fetch("binary_sha256")}"
      end

      version, = run(real_path, "--version")
      first_line = version.lines.first.to_s.strip
      unless first_line == lock_runtime.fetch(name).fetch("version")
        raise BuildError,
              "extracted #{name} reports #{first_line.inspect}, lock expects #{lock_runtime.fetch(name).fetch("version").inspect}"
      end

      runtime[name] = {
        "path" => real_path,
        "version" => first_line,
        "binary_sha256" => sha,
        "identity_method" => "realpath+version+binary_sha256",
        "in_image_path" => in_image_path,
        "extracted_from" => reference
      }
    end
    runtime
  ensure
    docker("rm", "-f", container, allow_failure: true) if container
  end

  def github_commit(repository_api, ref)
    uri = URI("https://api.github.com/repos/#{repository_api}/commits/#{ref}")
    response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 20, read_timeout: 60) do |http|
      request = Net::HTTP::Get.new(uri)
      request["Accept"] = "application/vnd.github+json"
      request["User-Agent"] = "rubernetes-m2-lifecycle-oracle"
      http.request(request)
    end
    raise BuildError, "GitHub commit lookup for #{ref} returned #{response.code}" unless response.is_a?(Net::HTTPSuccess)

    document = JSON.parse(response.body)
    sha = document["sha"].to_s
    raise BuildError, "GitHub returned no commit for #{ref}" unless sha.match?(/\A[0-9a-f]{40}\z/)

    {"sha" => sha, "date" => document.dig("commit", "committer", "date"),
     "subject" => document.dig("commit", "message").to_s.lines.first.to_s.strip}
  end

  # Observe the rendered CNI config on a throwaway single-node cluster; this is
  # what kindnetd writes at runtime and what the harness re-verifies.
  def observe_cni_config!(kind, reference, alias_image)
    name = "rubernetes-m2-node-image-cni-#{Process.pid}"
    network = name
    alias_container = "#{name}-hostalias"
    node = "#{name}-control-plane"
    scratch = Dir.mktmpdir("rubernetes-m2-node-image-")
    begin
      docker("network", "create", "--internal", network)
      docker("run", "-d", "--name", alias_container, "--network", network, "--network-alias", "host.docker.internal", alias_image)
      config = File.join(scratch, "kind.yaml")
      File.write(config,
                 "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnetworking:\n  apiServerAddress: 127.0.0.1\n  apiServerPort: " \
                 "#{API_SERVER_PORT}\nnodes:\n- role: control-plane\n")
      stdout, stderr, status = run(kind, "create", "cluster", "--name", name, "--image", reference, "--config", config, "--kubeconfig", File.join(scratch, "kubeconfig"), "--wait", "0", "--retain",
                                   env: {"KIND_EXPERIMENTAL_DOCKER_NETWORK" => network}, timeout: 600, allow_failure: true)
      unless status.success? || "#{stdout}#{stderr}".include?("failed to get api server port")
        raise BuildError,
              "kind create cluster failed: #{stdout}\n#{stderr}"
      end

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 240
      content = nil
      loop do
        stdout, _stderr, cat_status = docker("exec", node, "cat", CNI_CONFIG_PATH, allow_failure: true)
        if cat_status.success? && !stdout.empty?
          content = stdout
          break
        end
        raise BuildError, "#{CNI_CONFIG_PATH} was not written within 240s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

        sleep(1)
      end
      pods, = docker("exec", node, "kubectl", "--kubeconfig", "/etc/kubernetes/admin.conf", "get", "pods", "-n", "kube-system", "-l",
                     "app=kindnet", "-o", "json")
      image_id = nil
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 120
      loop do
        image_id = JSON.parse(pods).dig("items", 0, "status", "containerStatuses", 0, "imageID").to_s
        break unless image_id.empty?
        raise BuildError, "kindnet pod imageID was not reported within 120s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

        sleep(1)
        pods, = docker("exec", node, "kubectl", "--kubeconfig", "/etc/kubernetes/admin.conf", "get", "pods", "-n", "kube-system", "-l",
                       "app=kindnet", "-o", "json")
      end
      {"config" => content, "config_sha256" => Digest::SHA256.hexdigest(content), "kindnetd_image_id" => image_id}
    ensure
      run(kind, "delete", "cluster", "--name", name, "--kubeconfig", File.join(scratch, "kubeconfig"),
          env: {"KIND_EXPERIMENTAL_DOCKER_NETWORK" => network}, timeout: 300, allow_failure: true)
      docker("rm", "-f", node, alias_container, allow_failure: true)
      docker("network", "rm", network, allow_failure: true)
      FileUtils.rm_rf(scratch)
    end
  end

  def write_locks!(reuse_existing_image:, build_log_path: nil)
    lock = kind_lock
    kind = ensure_kind!(lock)
    source_root = ENV.fetch(SOURCE_ENV, "")
    verify_source_checkout!(source_root)
    base_image = lock.fetch("default_base_image").fetch("reference")
    _stdout, _stderr, present = docker("image", "inspect", LOCAL_TAG, allow_failure: true)
    built_at = nil
    if present.success? && reuse_existing_image
      warn("reusing existing #{LOCAL_TAG}")
    else
      built_at = Time.now.utc.iso8601
      warn("building #{LOCAL_TAG} from #{source_root} with #{kind} (this compiles Kubernetes)")
      run(kind, "build", "node-image", "--image", LOCAL_TAG, "--base-image", base_image, source_root, env: {"GOTOOLCHAIN" => "auto"},
                                                                                                      timeout: BUILD_TIMEOUT_SECONDS)
    end
    base_digest = repo_digests(base_image).find { |entry| entry.include?("@sha256:") }
    raise BuildError, "base image #{base_image} has no repo digest locally" unless base_digest

    docker("pull", "-q", REGISTRY_IMAGE) unless docker("image", "inspect", REGISTRY_IMAGE, allow_failure: true).last.success?
    docker("pull", "-q", "registry.k8s.io/pause:3.10") unless docker("image", "inspect", "registry.k8s.io/pause:3.10",
                                                                     allow_failure: true).last.success?
    pause_digest = repo_digests("registry.k8s.io/pause:3.10").find { |entry| entry.start_with?("registry.k8s.io/pause@sha256:") }
    raise BuildError, "pause image digest is unavailable" unless pause_digest

    pinned = pin_by_digest!(LOCAL_TAG)
    reference = pinned.fetch("reference")
    id = image_id(reference)
    unless id == image_id(LOCAL_TAG)
      raise BuildError,
            "digest reference #{reference} resolves to #{id}, local tag is #{image_id(LOCAL_TAG)}"
    end

    inspected = inspect_node_image(reference)
    raise BuildError, "node image kubelet reports #{inspected.dig("runtime", "kubelet", "version")}" unless inspected.dig("runtime",
                                                                                                                          "kubelet", "version") == "Kubernetes #{KUBERNETES_VERSION}"

    cni = observe_cni_config!(kind, reference, pause_digest)
    # Imported (not pulled) images expose their CRI image ID, not a repo digest,
    # through Pod status; the containerd name -> digest mapping is checked too.
    unless cni.fetch("kindnetd_image_id") == inspected.dig(
      "kindnetd", "cri_image_id"
    )
      raise BuildError,
            "kindnetd running imageID #{cni["kindnetd_image_id"]} is not the CRI image ID #{inspected.dig("kindnetd",
                                                                                                          "cri_image_id")}"
    end

    kind_commit = github_commit("kubernetes-sigs/kind", inspected.dig("kindnetd", "version").split("-").last)

    node_lock = {
      "schema_version" => 1,
      "verified_at" => Time.now.utc.strftime("%Y-%m-%d"),
      "purpose" => "M2 lifecycle oracle: Kubernetes #{KUBERNETES_VERSION} node image (kubelet, kubeadm, kube-apiserver, etcd, containerd, runc, kindnetd) " \
                   "built from the pinned source checkout",
      "image" => {
        "reference" => reference,
        "local_tag" => LOCAL_TAG,
        "image_id" => id,
        "repo_digest" => reference.split("@").last,
        "os_image" => inspected.fetch("os_image")
      },
      "build" => {
        "tool" => "kind build node-image",
        "kind_lock_path" => KIND_LOCK_RELATIVE_PATH,
        "kind_version" => lock.fetch("tag"),
        "kind_binary_sha256" => lock.fetch("artifacts").fetch("linux/amd64").fetch("sha256"),
        "base_image" => {"reference" => base_image, "digest_reference" => base_digest},
        "kubernetes" => {"tag" => KUBERNETES_VERSION, "commit" => KUBERNETES_SOURCE_COMMIT, "source_checkout_env" => SOURCE_ENV},
        "command" => [lock.fetch("install_path"), "build", "node-image", "--image", LOCAL_TAG, "--base-image", base_image,
                      "<#{SOURCE_ENV}>"],
        "built_at" => built_at,
        "build_log_sha256" => build_log_path && File.file?(build_log_path) ? Digest::SHA256.file(build_log_path).hexdigest : nil,
        "reused_existing_image" => built_at.nil?
      },
      "digest_pinning" => {
        "method" => "docker push to an ephemeral local registry (localhost, port >= 25000); the recorded RepoDigest resolves from the local image store without the registry",
        "registry_image" => pinned.fetch("registry_image")
      },
      "alias_container_image" => {
        "reference" => pause_digest,
        "purpose" => "answers host.docker.internal for the kind node entrypoint on the gateway-less internal network"
      },
      "cluster" => {"api_server_port" => API_SERVER_PORT, "network" => "docker network create --internal",
                    "provisioner" => "kind create cluster --retain (host port export is expected to fail on an internal network)"},
      "runtime" => inspected.fetch("runtime"),
      "images" => inspected.fetch("images"),
      "cri_image_ids" => inspected.fetch("cri_image_ids"),
      "cni_manifest_sha256" => inspected.fetch("cni_manifest_sha256")
    }
    node_lock["lock_sha256"] = canonical_digest(node_lock, excluded_keys: ["lock_sha256"])

    cni_lock = {
      "schema_version" => 1,
      "verified_at" => node_lock["verified_at"],
      "plugin" => "kindnetd",
      "version" => inspected.dig("kindnetd", "version"),
      "source_repository" => KIND_REPOSITORY,
      "source_path" => "images/kindnetd",
      "source_commit" => kind_commit.fetch("sha"),
      "source_commit_date" => kind_commit["date"],
      "image_reference" => inspected.dig("images", "kindnetd"),
      "image_digest" => inspected.dig("kindnetd", "digest").delete_prefix("sha256:"),
      "image_tag" => inspected.dig("kindnetd", "tag"),
      "cri_image_id" => inspected.dig("kindnetd", "cri_image_id"),
      "config_path" => CNI_CONFIG_PATH,
      "config_sha256" => cni.fetch("config_sha256"),
      "config" => cni.fetch("config"),
      "manifest_path" => "/kind/manifests/default-cni.yaml",
      "manifest_sha256" => inspected.fetch("cni_manifest_sha256"),
      "plugin_binaries" => inspected.fetch("cni_plugin_binaries"),
      "chained_plugins" => %w[ptp portmap],
      "ipam" => "host-local",
      "node_image_lock_path" => NODE_IMAGE_LOCK_RELATIVE_PATH,
      "node_image_reference" => reference
    }
    cni_lock["lock_sha256"] = canonical_digest(cni_lock, excluded_keys: ["lock_sha256"])

    File.write(NODE_IMAGE_LOCK_PATH, JSON.pretty_generate(node_lock) + "\n")
    File.write(CNI_LOCK_PATH, JSON.pretty_generate(cni_lock) + "\n")
    {"node_image_lock" => NODE_IMAGE_LOCK_RELATIVE_PATH, "cni_lock" => CNI_LOCK_RELATIVE_PATH, "image" => reference}
  end

  # Runner mode: verify the locked image is present and report identities.
  def report(input)
    unless input.is_a?(Hash) && input["kubernetes_version"] == KUBERNETES_VERSION && input["source_commit"] == KUBERNETES_SOURCE_COMMIT
      raise BuildError,
            "self-contained image request is not pinned to #{KUBERNETES_VERSION}"
    end

    lock = parse_json(NODE_IMAGE_LOCK_PATH)
    raise BuildError, "node image lock schema_version must be 1" unless lock["schema_version"] == 1
    raise BuildError, "node image lock digest does not match content" unless lock["lock_sha256"] == canonical_digest(lock,
                                                                                                                     excluded_keys: ["lock_sha256"])
    raise BuildError, "node image lock is not built from #{KUBERNETES_SOURCE_COMMIT}" unless lock.dig("build", "kubernetes",
                                                                                                      "commit") == KUBERNETES_SOURCE_COMMIT && lock.dig(
                                                                                                        "build", "kubernetes", "tag"
                                                                                                      ) == KUBERNETES_VERSION

    reference = lock.fetch("image").fetch("reference")
    raise BuildError, "node image lock reference is not digest-pinned" unless reference.match?(/\A[^@\s]+@sha256:[0-9a-f]{64}\z/)

    kind_lock_document = kind_lock
    raise BuildError, "node image lock kind binary SHA-256 does not match the kind lock" unless lock.dig("build",
                                                                                                         "kind_binary_sha256") == kind_lock_document.fetch("artifacts").fetch("linux/amd64").fetch("sha256")

    ensure_kind!(kind_lock_document)
    _stdout, stderr, status = docker("image", "inspect", "--format", "{{.Id}}", reference, allow_failure: true)
    unless status.success?
      raise BuildError,
            "locked node image #{reference} is not in the local Docker image store (#{stderr.strip}); run `ruby #{File.basename(__FILE__)} --write-lock` after building"
    end

    id = image_id(reference)
    unless id == lock.fetch("image").fetch("image_id")
      raise BuildError,
            "node image #{reference} has ID #{id}, lock expects #{lock.fetch("image").fetch("image_id")}"
    end

    runtime = extract_runtime!(reference, id, lock.fetch("runtime"))
    {
      "image" => reference,
      "image_id" => id,
      "kubernetes_version" => KUBERNETES_VERSION,
      "source_commit" => KUBERNETES_SOURCE_COMMIT,
      "runtime" => runtime,
      "images" => lock.fetch("images"),
      "kind" => {"version" => kind_lock_document.fetch("tag"),
                 "binary_sha256" => kind_lock_document.fetch("artifacts").fetch("linux/amd64").fetch("sha256")},
      "base_image" => lock.dig("build", "base_image"),
      "node_image_lock_sha256" => lock.fetch("lock_sha256"),
      "builder_sha256" => Digest::SHA256.file(__FILE__).hexdigest
    }
  end

  def main(argv)
    if argv.include?("--write-lock")
      log_index = argv.index("--build-log")
      result = write_locks!(reuse_existing_image: argv.include?("--reuse-existing-image"), build_log_path: log_index && argv[log_index + 1])
      puts JSON.pretty_generate(result)
      return 0
    end
    input = JSON.parse($stdin.read, max_nesting: 512)
    puts JSON.generate(report(input))
    0
  rescue BuildError, SystemCallError, KeyError, JSON::ParserError, SocketError, Timeout::Error => error
    warn("m2 lifecycle node image: #{error.class}: #{error.message}")
    puts JSON.generate({"error" => "#{error.class}: #{error.message}"})
    1
  end
end

exit(M2LifecycleOracleNodeImage.main(ARGV)) if $PROGRAM_NAME == __FILE__
