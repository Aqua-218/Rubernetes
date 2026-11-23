# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/volume"
require "tmpdir"

class ProjectedVolumeSourcesTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir
    @now = Time.utc(2026, 1, 1)
    @issued = []
    @provider = lambda do |audience:, **|
      value = "issued-#{audience}-#{@issued.size}"
      @issued << value
      value
    end
    @objects = {}
    start_node
  end

  def start_node
    @manager = Rubernetes::Volume::Manager.new(data_dir: @dir, token_provider: @provider, clock: -> { @now }, fsync: true)
    @volumes = Rubernetes::Node::PodVolumes.new(volume: @manager, reader: self, root: File.join(@dir, "pods"))
  end

  def teardown
    @volumes.release(@pod, @handle) if @handle
    FileUtils.remove_entry(@dir)
  end

  def get(resource, name, namespace:)
    @objects.fetch([resource, name])
  end

  def prepare(sources)
    @pod = {"metadata" => {"uid" => "p", "name" => "p"}, "spec" => {
      "volumes" => [{"name" => "settings", "projected" => {"defaultMode" => 0o664, "sources" => sources}}],
      "containers" => [{"name" => "reader", "volumeMounts" => [{"name" => "settings", "mountPath" => "/settings"}]}]
    }}
    @handle = @volumes.prepare(@pod)
    @path = @handle.dig("mounts", "settings", "path")
  end

  def read(name)
    File.binread(File.join(@path, name))
  end

  def mode(name)
    File.stat(File.join(@path, name)).mode & 0o777
  end

  def mount_at(path)
    @manager.mount_adapter.list_mounts.find { |mount| mount["target"] == path }
  end

  def ledger_contents(name)
    records = Dir[File.join(@dir, "#{name}.json.d", "*.json")]

    refute_empty records
    records.map { |path| File.binread(path) }.join
  end

  def test_later_sources_replace_both_bytes_and_mode_and_can_disappear
    shared = "same bytes"
    @objects[%w[configmaps base]] = {"data" => {"k" => shared}}
    secret = @objects[%w[secrets overlay]] = {"data" => {"mode" => Base64.strict_encode64(shared),
                                                         "serviceAccountToken" => Base64.strict_encode64("\xff\0".b)}}
    prepare([{}, {"configMap" => {"name" => "base", "items" => [{"key" => "k", "path" => "mode", "mode" => 0o400}]}},
             {"secret" => {"name" => "overlay", "items" => []}}])

    assert_equal shared, read("mode")
    assert_equal 0o664, mode("mode")
    assert_equal "\xff\0".b, read("serviceAccountToken")
    assert_equal "tmpfs", mount_at(@path).fetch("filesystem")
    %w[operations volumes].each do |ledger|
      refute_includes ledger_contents(ledger), Base64.strict_encode64("\xff\0".b)
    end
    assert_empty @volumes.refresh_contents(@pod, @handle)
    original_link = File.lstat(File.join(@path, "mode")).ino
    secret.fetch("data").delete("mode")

    assert_equal ["settings"], @volumes.refresh_contents(@pod, @handle)
    assert_equal shared, read("mode")
    assert_equal 0o400, mode("mode")
    assert_equal original_link, File.lstat(File.join(@path, "mode")).ino
    assert_empty @volumes.refresh_contents(@pod, @handle)
  end

  def test_public_projections_use_tmpfs_and_keep_public_records
    @objects[%w[configmaps cfg]] = {"data" => {"key" => "public-value"}}
    prepare([{"configMap" => {"name" => "cfg"}}])
    backend = @manager.backends.fetch(@handle.dig("mounts", "settings", "id"))

    refute_predicate backend, :secret?
    assert_equal "tmpfs", mount_at(@path).fetch("filesystem")
    assert_equal "public-value", read("key")
    assert_includes ledger_contents("volumes"), "public-value"
    @volumes.release(@pod, @handle)
    @handle = nil

    assert_nil mount_at(@path)
  end

  def test_raw_downward_and_projected_volumes_publish_the_same_pod_fields
    pod = {"metadata" => {"name" => "shop", "annotations" => {"example.com/team" => "日本\u00a0語\a"}},
           "spec" => {"containers" => [{"name" => "web", "resources" => {"requests" => {"cpu" => "125m"}}}]}}
    items = [{"path" => "team", "fieldRef" => {"fieldPath" => "metadata.annotations['example.com/team']"}, "mode" => 0o400},
             {"path" => "annotations", "fieldRef" => {"fieldPath" => "metadata.annotations"}},
             {"path" => "cpu", "resourceFieldRef" => {"containerName" => "web", "resource" => "requests.cpu", "divisor" => "1m"}}]
    expected = {"team" => "日本\u00a0語\a", "annotations" => 'example.com/team="日本\u00a0語\a"', "cpu" => "125"}
    specs = [{"downwardAPI" => {"items" => items}}, {"projected" => {"sources" => [{"downwardAPI" => {"items" => items}}]}}]
    specs.each do |spec|
      name = spec.keys.first.downcase
      id = @manager.create_volume({"name" => name, "pod" => pod, "defaultMode" => 0o640}.merge(spec), token: name)
      root = @manager.backends.fetch(id).source_path

      assert_equal expected, expected.keys.to_h { |path| [path, File.read(File.join(root, path))] }, name
      assert_equal [0o400, 0o640], %w[team cpu].map { |path| File.stat(File.join(root, path)).mode & 0o777 }, name
      @manager.delete_volume(id, token: "remove-#{name}")
    end
  end

  def test_bound_token_request_rejected_before_mount_leaves_no_volume_to_recover
    @provider = ->(**) { raise Rubernetes::Volume::NotFoundError, "bound Pod no longer exists" }
    start_node
    assert_raises(Rubernetes::Volume::NotFoundError) do
      prepare([{"serviceAccountToken" => {"path" => "token"}}])
    end
    assert_empty @manager.list_volumes
    assert_empty @manager.mount_ledger.entries
    assert_empty @manager.mount_adapter.list_mounts
    start_node

    assert_empty @manager.list_volumes
  end

  def test_recovery_discards_only_unmounted_legacy_declarations
    record_type = Rubernetes::Volume::VolumeRecord
    %w[abandoned observed incomplete provisioned queued].each do |id|
      previous = id == "provisioned" ? "Provisioned" : "Declared"
      @manager.volume_store[id] = record_type.new(id: id, backend: "projected", state: "Unknown",
                                                  spec: {"backend" => "projected", "sources" => []}, operation: {"previousState" => previous})
    end
    start_node
    path = @manager.backends.fetch("incomplete").source_path
    FileUtils.mkdir_p(path)
    File.write(File.join(path, "data"), "keep")
    @manager.operations.begin!(key: "queued", operation: "create", token: "pending", fingerprint: "queued")
    report = @manager.recover(observed_mounts: [{"target" => @manager.backends.fetch("observed").source_path}])

    assert_equal(%w[incomplete observed provisioned queued], report.unknown.map { |entry| entry["id"] || entry["key"] }.sort)
    start_node

    assert_equal %w[incomplete observed provisioned queued], @manager.list_volumes.map(&:id).sort
    assert_equal "keep", File.read(File.join(path, "data"))
  end

  def test_failed_setup_refuses_to_remove_an_unrecorded_mount_or_nonempty_directory
    backend = @manager.build_backend("unrecorded", {"backend" => "projected", "sources" => []})
    FileUtils.mkdir_p(backend.source_path)
    file = File.join(backend.source_path, "other")
    File.write(file, "unclaimed")

    assert_raises(Errno::ENOTEMPTY) { backend.delete }
    assert_equal "unclaimed", File.read(file)
    File.unlink(file)
    @manager.mount_adapter.ensure_tmpfs(backend.source_path)

    assert_raises(Rubernetes::Volume::MountIdentityError) { backend.delete }
    assert_equal "tmpfs", mount_at(backend.source_path).fetch("filesystem")
  end

  def test_downward_api_stores_pod_metadata_on_tmpfs
    @pod = {"metadata" => {"uid" => "meta", "name" => "example"}, "spec" => {
      "volumes" => [{"name" => "info", "downwardAPI" => {"items" => [{"path" => "name", "fieldRef" => {"fieldPath" => "metadata.name"}}]}}],
      "containers" => [{"name" => "reader", "volumeMounts" => [{"name" => "info", "mountPath" => "/info"}]}]
    }}
    @handle = @volumes.prepare(@pod)
    @path = @handle.dig("mounts", "info", "path")

    assert_equal "tmpfs", mount_at(@path).fetch("filesystem")
    assert_equal "example", read("name")
  end

  def test_resolved_file_volumes_do_not_duplicate_the_entire_pod_in_each_record
    marker = "large-unrelated-pod-annotation" * 2_000
    items = [{"path" => "name", "fieldRef" => {"fieldPath" => "metadata.name"}}]
    definitions = [{"name" => "direct", "downwardAPI" => {"items" => items}},
                   {"name" => "combined", "projected" => {"sources" => [{"downwardAPI" => {"items" => items}}]}}]
    @pod = {"metadata" => {"uid" => "files", "name" => "app", "annotations" => {"example.org/note" => marker}}, "spec" => {
      "volumes" => definitions, "containers" => [{"name" => "app", "volumeMounts" => definitions.map do |volume|
        {"name" => volume.fetch("name"), "mountPath" => "/#{volume.fetch("name")}"}
      end}]
    }}
    @handle = @volumes.prepare(@pod)

    %w[operations volumes].each { |ledger| refute_includes ledger_contents(ledger), marker }
    start_node

    assert_equal %w[direct combined], @volumes.refresh_contents(@pod, @handle)
    @handle.fetch("mounts").each_value do |mount|
      assert_equal "app", File.read(File.join(mount.fetch("path"), "name"))
    end
  end

  def test_refresh_retries_failed_group_ownership_and_publishes_status_only_once
    prepare([{"downwardAPI" => {"items" => [{"path" => "ip", "fieldRef" => {"fieldPath" => "status.podIP"}}]}}])
    @pod.fetch("spec")["securityContext"] = {"fsGroup" => 1200}
    calls = 0
    @manager.define_singleton_method(:reapply_fs_group) do |*, **|
      calls += 1
      raise Errno::EIO if calls == 1
    end
    @volumes.refresh(@pod, @handle, pod_ips: ["10.0.0.8"])

    assert_equal ["settings"], @volumes.refresh_contents(@pod, @handle, pod_ips: ["10.0.0.8"])
    generation = File.readlink(File.join(@path, "..data"))

    assert @volumes.refresh(@pod, @handle, pod_ips: ["10.0.0.8"])
    assert_empty @volumes.refresh_contents(@pod, @handle, pod_ips: ["10.0.0.8"])
    assert_equal "10.0.0.8", read("ip")
    assert_equal generation, File.readlink(File.join(@path, "..data"))
    assert_equal 2, calls
  end

  def test_unordered_map_readback_does_not_rewrite_projected_files
    config = @objects[%w[configmaps cfg]] = {"data" => {"a" => "first", "b" => "second"},
                                             "binaryData" => {"bytes" => Base64.strict_encode64("\xff".b)}}
    prepare([{"configMap" => {"name" => "cfg"}}])
    generation = File.readlink(File.join(@path, "..data"))
    config["data"] = config.fetch("data").to_a.reverse.to_h

    assert_empty @volumes.refresh_contents(@pod, @handle)
    assert_equal generation, File.readlink(File.join(@path, "..data"))
    assert_equal "\xff".b, read("bytes")
  end

  def test_direct_config_map_refresh_handles_arbitrary_bytes_and_reordered_keys
    config = @objects[%w[configmaps cfg]] = {"data" => {"a" => "first", "b" => "second"},
                                             "binaryData" => {"bytes" => Base64.strict_encode64("\xff\0".b)}}
    @pod = {"metadata" => {"uid" => "direct", "name" => "direct"}, "spec" => {
      "volumes" => [{"name" => "settings", "configMap" => {"name" => "cfg"}}],
      "containers" => [{"name" => "reader", "volumeMounts" => [{"name" => "settings", "mountPath" => "/settings"}]}]
    }}
    @handle = @volumes.prepare(@pod)
    @path = @handle.dig("mounts", "settings", "path")
    generation = File.readlink(File.join(@path, "..data"))
    config["data"] = config.fetch("data").to_a.reverse.to_h

    assert_empty @volumes.refresh_contents(@pod, @handle)
    assert_equal generation, File.readlink(File.join(@path, "..data"))
    assert_equal "\xff\0".b, read("bytes")
    config.fetch("binaryData")["bytes"] = Base64.strict_encode64("\0\xfe".b)

    assert_equal ["settings"], @volumes.refresh_contents(@pod, @handle)
    assert_equal "\0\xfe".b, read("bytes")
  end

  def test_recovery_restores_lost_tmpfs_and_republishes_unchanged_source
    @objects[%w[configmaps cfg]] = {"data" => {"key" => "unchanged"}}
    prepare([{"configMap" => {"name" => "cfg"}}])
    @manager.mount_adapter.unmount(target: @path)
    File.unlink(File.join(@path, "..data"))
    report = @manager.recover

    assert_empty report.errors
    assert_equal "tmpfs", mount_at(@path).fetch("filesystem")
    assert_equal ["settings"], @volumes.refresh_contents(@pod, @handle)
    assert_equal "unchanged", read("key")
    assert_empty @volumes.refresh_contents(@pod, @handle)
  end

  # After a host reboot the recorded tmpfs is gone and a fresh one sits at the
  # volume's private path.  Its deletion must remove that tmpfs instead of
  # refusing for ever ("mount identity changed ... mountId mismatch").
  def test_a_tmpfs_remounted_after_a_reboot_is_released
    @objects[%w[configmaps cfg]] = {"data" => {"key" => "value"}}
    prepare([{"configMap" => {"name" => "cfg"}}])
    source = mount_at(@path) ? @path : @handle.dig("mounts", "settings", "path")
    adapter = @manager.mount_adapter
    stage = adapter.list_mounts.find { |mount| mount["filesystem"] == "tmpfs" }.fetch("target")
    adapter.unmount(target: stage)
    adapter.ensure_tmpfs(stage)
    replaced = adapter.list_mounts.find { |mount| mount["target"] == stage }

    skip "the in-memory adapter reuses the mount id" if replaced.nil?

    @volumes.release(@pod, @handle)
    @handle = nil

    refute(adapter.list_mounts.any? { |mount| mount["target"] == stage }, "the replacement tmpfs must be unmounted (#{source})")
  end

  def test_existing_public_directory_survives_backend_reconstruction
    spec = {"backend" => "projected", "name" => "settings", "sources" => [{"k" => "first"}],
            "backendResult" => {"backend" => "projected", "mountIdentity" => nil}}
    backend = @manager.build_backend("old", spec)
    FileUtils.mkdir_p(backend.source_path)
    backend.update(sources: [{"k" => "after-restart"}])

    assert_equal "after-restart", File.read(File.join(backend.source_path, "k"))
    assert_nil mount_at(backend.source_path)
    assert_raises(Rubernetes::Volume::SecretPersistenceError) do
      backend.update(sources: [{"secret" => {"stringData" => {"password" => "private"}}}])
    end
    refute_path_exists File.join(backend.source_path, "password")
    backend.delete

    refute_path_exists backend.source_path
  end

  def test_restarted_node_rehydrates_tokens_and_secrets_from_their_providers
    secret = @objects[%w[secrets cfg]] = {"stringData" => {"config" => "from-first-read"}}
    prepare([{"serviceAccountToken" => {"path" => "jwt", "audience" => "api"}},
             {"secret" => {"name" => "cfg"}}])

    assert_equal "issued-api-0", read("jwt")
    assert_equal "from-first-read", read("config")
    refute_includes ledger_contents("operations"), "from-first-read"
    refute_includes ledger_contents("volumes"), "from-first-read"
    secret["stringData"]["config"] = "latest-read"
    start_node

    assert_equal ["settings"], @volumes.rotate_tokens(@pod, @handle, now: @now)
    assert_equal "issued-api-1", read("jwt")
    assert_equal "latest-read", read("config")
    assert_empty @volumes.refresh_contents(@pod, @handle)
  end

  def test_each_token_refresh_preserves_later_files_and_updated_sources
    config = @objects[%w[configmaps overlay]] = {"data" => {"hidden" => "first"}}
    prepare([{"serviceAccountToken" => {"path" => "hidden", "audience" => "one", "expirationSeconds" => 600}},
             {"serviceAccountToken" => {"path" => "visible", "audience" => "two", "expirationSeconds" => 1200}},
             {"configMap" => {"name" => "overlay"}}])

    assert_equal "first", read("hidden")
    assert_equal "issued-two-1", read("visible")
    config.fetch("data")["hidden"] = "second"

    assert_equal ["settings"], @volumes.refresh_contents(@pod, @handle)
    assert_equal 2, @issued.size
    @now += 500

    assert_equal ["settings"], @volumes.rotate_tokens(@pod, @handle, now: @now)
    assert_equal "second", read("hidden")
    assert_equal "issued-two-1", read("visible")
    config.fetch("data").clear

    assert_equal ["settings"], @volumes.refresh_contents(@pod, @handle)
    assert_equal "issued-one-2", read("hidden")
    @now += 470

    assert_equal ["settings"], @volumes.rotate_tokens(@pod, @handle, now: @now)
    assert_equal "issued-two-3", read("visible")
    ledger = ledger_contents("operations")

    @issued.each { |value| refute_includes ledger, value }
  end

  def test_token_refresh_keeps_valid_files_on_failure_and_repeats_original_request
    requests = []
    available = true
    @provider = lambda do |ttl:, **|
      requests << ttl
      raise IOError, "TokenRequest temporarily unavailable" unless available

      {"token" => "token-#{requests.size}", "expiresAt" => @now + 900}
    end
    start_node
    prepare([{"serviceAccountToken" => {"path" => "jwt"}}])
    generation = File.readlink(File.join(@path, "..data"))
    @now += 725
    available = false

    assert_empty @volumes.rotate_tokens(@pod, @handle, now: @now)
    assert_equal "token-1", read("jwt")
    assert_equal generation, File.readlink(File.join(@path, "..data"))
    available = true
    @now += 5

    assert_equal ["settings"], @volumes.rotate_tokens(@pod, @handle, now: @now)
    assert_equal "token-3", read("jwt")
    assert_equal [3600, 3600, 3600], requests
    available = false
    @now += 901

    assert_raises(IOError) { @volumes.rotate_tokens(@pod, @handle, now: @now) }
  end

  def test_multi_day_projected_token_is_renewed_within_24_hours
    prepare([{"serviceAccountToken" => {"path" => "jwt", "expirationSeconds" => 259_200}}])
    @now += 86_380

    assert_empty @volumes.rotate_tokens(@pod, @handle, now: @now)
    @now += 20

    assert_equal ["settings"], @volumes.rotate_tokens(@pod, @handle, now: @now)
    assert_equal "issued--1", read("jwt")
  end
end
