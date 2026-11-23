# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/conformance/run"

class ConformanceK0InputIntegrityTest < Minitest::Test
  K0 = Conformance::K0
  L = Conformance::Lock
  RUNNER = Conformance::Runner
  IMAGE = "example.test/fixture:release"
  PLATFORM = "linux/amd64"
  OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
  OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
  OCI_INDEX = "application/vnd.oci.image.index.v1+json"

  def test_git_worktree_at_the_pinned_tag_and_head
    with_repo do |repo, parent, pin|
      linked = File.join(parent, "linked")
      git(repo, "worktree", "add", "--detach", linked, pin.fetch("commit"))
      L.stub(:kubernetes, {"source" => pin}) do
        assert K0.source_identity(linked).fetch("passed")
        assert K0.source_cleanliness(linked).fetch("passed")
        File.write(File.join(repo, "tracked"), "different commit")
        git(repo, "commit", "-am", "move HEAD")
        result = K0.source_identity(repo)

        refute result.fetch("passed")
        assert_equal pin.fetch("commit"), result.fetch("observed_commit")
        refute_equal result.fetch("observed_commit"), result.fetch("observed_head")
      end
    end
  end

  def test_export_marker_does_not_prove_a_clean_pinned_worktree
    with_repo do |parent, _directory, pin|
      export = File.join(parent, "export")
      Dir.mkdir(export)
      File.write(File.join(export, ".rubernetes-source-commit"), pin.fetch("commit"))
      L.stub(:kubernetes, {"source" => pin}) do
        refute K0.source_identity(export).fetch("passed")
        refute K0.source_cleanliness(export).fetch("passed")
      end
    end
  end

  def test_hidden_tracked_changes_and_ignored_vendor_entries_are_reported
    with_repo do |repo, _directory, _pin|
      git(repo, "update-index", "--assume-unchanged", "tracked")
      File.write(File.join(repo, "tracked"), "hidden worktree edit")
      File.write(File.join(repo, "vendor", "ignored"), "untracked dependency")
      result = K0.source_cleanliness(repo)

      refute result.fetch("passed")
      assert_equal 0, result.fetch("dirty_count")
      assert_equal ["h tracked"], result.fetch("hidden_tracked_entries")
      assert_equal ["vendor/ignored"], result.fetch("untracked_vendor_entries")
    end
  end

  def test_locked_images_validate_the_fetched_bytes_and_selected_platform
    documents, lock = registry_documents("one")
    factory = registry_factory(documents)
    parsed = K0.registry_manifest(lock, PLATFORM, factory)

    assert parsed.fetch("matches")
    assert_equal lock.dig("platforms", PLATFORM), parsed.fetch("observed_platform_digest")
    incorrect = lock.merge("platforms" => {PLATFORM => digest("another manifest")})

    refute K0.registry_manifest(incorrect, PLATFORM, factory).fetch("matches")
    refute K0.registry_manifest(lock, "linux/arm64", factory).fetch("matches")
    documents[lock.fetch("index_digest")] += "\n"
    corrupted = K0.registry_manifest(lock, PLATFORM, factory)

    refute corrupted.fetch("matches")
    assert_match(/digest/i, corrupted.fetch("error"))
  end

  def test_upstream_image_recheck_detects_moved_and_missing_public_tags
    first, = registry_documents("one")
    observed = K0::E2EImages.observe([IMAGE], PLATFORM, registry_client: registry_factory(first))

    assert_equal "resolved", observed.fetch(IMAGE).fetch("status")
    second, = registry_documents("two")
    moved = K0::E2EImages.stability(observed, PLATFORM, registry_client: registry_factory(second))

    refute moved.fetch("passed")
    assert_equal IMAGE, moved.fetch("mismatches").first.fetch("reference")

    missing = K0::E2EImages.stability(observed, PLATFORM, registry_client: registry_factory({}))

    refute missing.fetch("passed")
    assert_equal "unresolved", missing.dig("mismatches", 0, "after", "status")
  end

  def test_kubeconfig_compares_normalized_servers_and_actual_file_credentials
    Dir.mktmpdir do |directory|
      target = File.join(directory, "target.conf")
      oracle = File.join(directory, "oracle.conf")
      token = "isolated-test-credential"
      File.write(File.join(directory, "token"), "#{token}\n")
      key, certificate = self_signed_client
      File.binwrite(File.join(directory, "client.crt"), certificate.to_pem)
      File.binwrite(File.join(directory, "client.key"), key.to_pem)
      configure(target, "https://api.example.test:443", {"tokenFile" => "token", "client-certificate" => "client.crt", "client-key" => "client.key"})
      configure(oracle, "https://API.EXAMPLE.TEST./", {"token" => token, "client-certificate-data" => Base64.strict_encode64(certificate.to_der),
                                                       "client-key-data" => Base64.strict_encode64(key.private_to_der)})
      result = K0.kubeconfig_isolation(target, oracle)

      refute result.fetch("passed")
      assert_equal 1, result.fetch("shared_server_count")
      assert_equal 3, result.fetch("shared_credential_count")
      refute_includes JSON.generate(result), token
      refute_includes JSON.generate(result), "client.key"

      configure(oracle, "https://oracle.example.test", {"token" => "separate"})

      assert K0.kubeconfig_isolation(target, oracle).fetch("passed")

      configure(oracle, "https://oracle.example.test", {"tokenFile" => "missing"})

      refute K0.kubeconfig_isolation(target, oracle).fetch("passed")
    end
  end

  def test_unavailable_oracle_and_dynamic_credentials_do_not_pass_isolation
    Dir.mktmpdir do |directory|
      target = File.join(directory, "target.conf")
      oracle = File.join(directory, "oracle.conf")
      configure(target, "https://target.example.test", {"token" => "target"})

      refute K0.kubeconfig_isolation(target, oracle).fetch("passed")
      refute K0.kubeconfig_isolation(target, nil).fetch("oracle_compared")

      configure(oracle, "https://oracle.example.test", {"exec" => {"command" => "unavailable-command"}})

      refute K0.kubeconfig_isolation(target, oracle).fetch("passed")
    end
  end

  def test_failed_preflight_leaves_a_create_only_manifest_and_does_not_run_cluster_lanes
    check = {"lane" => "K0", "passed" => false, "platform" => PLATFORM, "cases" => [
      {"id" => "source_identity", "observed_head" => "wrong"},
      {"id" => "kubeconfig_isolation", "cluster_id" => "target-id"},
      {"id" => "image_manifests", "images" => {}},
      {"id" => "upstream_image_inventory", "images" => {}}
    ]}
    options = {lanes: %w[K1 K0], platform: PLATFORM}
    Dir.mktmpdir do |directory|
      K0.stub(:run, check) do
        Conformance::Lanes::K1.stub(:run, ->(**) { flunk "K1 must not run when preflight failed" }) do
          result = RUNNER.execute_lanes(options, profile: {"name" => "unit"}, directory: directory, run_id: "unique-run")

          assert_equal(%w[FAILED INCOMPLETE], result.map { |entry| entry.fetch("status") })
          assert_equal(%w[K0 K1], result.map { |entry| entry.fetch("lane") })
          path = File.join(directory, "k0", "inputs.json")
          frozen = JSON.parse(File.read(path))

          assert_equal "unique-run", frozen.fetch("runId")
          assert_equal "target-id", frozen.fetch("clusterId")
          assert_equal 0, File.stat(path).mode & 0o222
          assert_raises(Errno::EEXIST) { K0.record_inputs(File.dirname(path), check, run_id: "duplicate", profile: "unit") }
        end
      end
    end
  end

  def test_end_of_run_image_change_invalidates_k0_without_rewriting_initial_receipt
    images = {IMAGE => {"status" => "resolved", "digest" => digest("before")}}
    check = {"lane" => "K0", "passed" => true, "platform" => PLATFORM, "cases" => [
      {"id" => "source_identity", "observed_head" => L.source_commit},
      {"id" => "kubeconfig_isolation", "cluster_id" => "target-id"},
      {"id" => "image_manifests", "images" => {}},
      {"id" => "upstream_image_inventory", "images" => images}
    ]}
    stability = {"id" => "upstream_image_stability", "passed" => false}
    options = {lanes: %w[K0 K1], platform: PLATFORM}
    Dir.mktmpdir do |directory|
      K0.stub(:run, check) do
        K0::E2EImages.stub(:stability, stability) do
          Conformance::Lanes::K1.stub(:run, {"passed" => true}) do
            result = RUNNER.execute_lanes(options, profile: {"name" => "unit"}, directory: directory, run_id: "unique-run")

            assert_equal(%w[FAILED COMPLETE], result.map { |entry| entry.fetch("status") })
            refute RUNNER.summarize(result).fetch("passed")
            recorded = JSON.parse(File.read(File.join(directory, "k0", "resolved-images.json")))

            assert_equal images, recorded.fetch("upstream")
          end
        end
      end
    end
  end

  private

  def with_repo
    Dir.mktmpdir do |parent|
      root = File.join(parent, "source")
      Dir.mkdir(root)
      git(root, "init", "--quiet")
      Dir.mkdir(File.join(root, "vendor"))
      File.write(File.join(root, "tracked"), "pinned")
      File.write(File.join(root, "vendor", "required"), "dependency")
      File.write(File.join(root, ".gitignore"), "vendor/ignored\n")
      git(root, "add", ".")
      git(root, "commit", "-m", "source snapshot")
      git(root, "tag", "-a", "v1.test", "-m", "source release")
      yield root, parent, {"tag" => "v1.test", "commit" => git(root, "rev-parse", "HEAD"), "tag_object" => git(root, "rev-parse", "v1.test")}
    end
  end

  def git(root, *)
    config = ["-c", "user.email=test@example.test", "-c", "user.name=Test", "-c", "commit.gpgSign=false", "-c", "tag.gpgSign=false"]
    out, error, status = Open3.capture3("git", "-C", root, *config, *)
    raise error unless status.success?

    out.strip
  end

  def digest(bytes) = "sha256:#{Digest::SHA256.hexdigest(bytes)}"

  def descriptor(bytes, media_type)
    {"mediaType" => media_type, "digest" => digest(bytes), "size" => bytes.bytesize}
  end

  def registry_documents(annotation)
    config = descriptor("{}", OCI_CONFIG)
    child = JSON.generate("schemaVersion" => 2, "mediaType" => OCI_MANIFEST, "config" => config, "layers" => [],
                          "annotations" => {"org.example.note" => annotation})
    platform = {"platform" => {"os" => "linux", "architecture" => "amd64"}}
    index = JSON.generate("schemaVersion" => 2, "mediaType" => OCI_INDEX, "manifests" => [descriptor(child, OCI_MANIFEST).merge(platform)])
    lock = {"reference" => IMAGE, "index_digest" => digest(index), "platforms" => {PLATFORM => digest(child)}}
    [{"release" => index, digest(index) => index, digest(child) => child}, lock]
  end

  def registry_factory(documents)
    transport = lambda do |uri:, **|
      bytes = documents[uri.path.split("/").last]
      bytes ? {status: 200, body: bytes} : {status: 404, body: ""}
    end
    ->(reference) { Rubernetes::Image::RegistryClient.new(reference, transport: transport) }
  end

  def configure(path, server, user)
    document = {
      "apiVersion" => "v1", "kind" => "Config",
      "current-context" => "selected",
      "clusters" => [{"name" => "selected", "cluster" => {"server" => server}}],
      "contexts" => [{"name" => "selected", "context" => {"cluster" => "selected", "user" => "owner"}}],
      "users" => [{"name" => "owner", "user" => user}]
    }
    File.write(path, YAML.dump(document))
  end

  def self_signed_client
    key = OpenSSL::PKey::RSA.new(2048)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = 1
    certificate.subject = certificate.issuer = OpenSSL::X509::Name.parse("/CN=fixture")
    certificate.public_key = key
    certificate.not_before = Time.now
    certificate.not_after = Time.now + 60
    certificate.sign(key, OpenSSL::Digest.new("SHA256"))
    [key, certificate]
  end
end
