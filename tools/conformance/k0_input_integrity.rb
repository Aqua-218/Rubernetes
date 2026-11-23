#!/usr/bin/env ruby
# frozen_string_literal: true

# K0 — Input Integrity (spec/verification/kubernetes-compatibility.md#k0).
#
# Runs before the runner touches a cluster.  Every check reads the pinned
# locks and the real checkout; a mismatch is a test failure and the lock is
# never refreshed from the network to make a check pass.

require "digest"
require "fileutils"
require "json"
require "open3"

require_relative "lock"
require_relative "k0_kubeconfig"
require_relative "k0_e2e_images"
require_relative "../../lib/rubernetes/image"

module Conformance
  module K0
    L = Conformance::Lock
    ROOT = L::ROOT
    Image = Rubernetes::Image
    GIT_ENV = %w[GIT_DIR GIT_COMMON_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY
                 GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE GIT_CONFIG GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT].to_h { |key| [key, nil] }.freeze

    module_function

    def run(source_root:, platform: "linux/amd64", kubeconfig: nil, oracle_kubeconfig: nil)
      identity = source_identity(source_root)
      cleanliness = source_cleanliness(source_root)
      cases = [identity, cleanliness, conformance_definition(source_root), runner_artifacts(platform), image_manifests(platform),
               kubeconfig_isolation(kubeconfig, oracle_kubeconfig)]
      cases << if identity["passed"] && cleanliness["passed"]
                 E2EImages.verify(source_root, platform)
               else
                 {"id" => "upstream_image_inventory", "passed" => false, "error" => "source checkout did not pass preflight"}
               end
      {
        "lane" => "K0",
        "passed" => cases.all? { |entry| entry.fetch("passed") },
        "platform" => platform,
        "cases" => cases
      }
    end

    # 1. The annotated tag and the checked-out commit both match the lock.
    def source_identity(source_root)
      source = L.kubernetes.fetch("source")
      tag = "refs/tags/#{source.fetch("tag")}"
      worktree = git_worktree?(source_root)
      observed_head = git(source_root, "rev-parse", "--verify", "HEAD^{commit}") if worktree
      observed_commit = git(source_root, "rev-parse", "--verify", "#{tag}^{commit}") if worktree
      observed_tag = git(source_root, "rev-parse", "--verify", "#{tag}^{tag}") if worktree
      {
        "id" => "source_identity",
        "passed" => worktree && observed_head == L.source_commit && observed_commit == L.source_commit && observed_tag == L.tag_object,
        "expected_commit" => L.source_commit,
        "observed_head" => observed_head,
        "observed_commit" => observed_commit,
        "expected_tag_object" => L.tag_object,
        "observed_tag_object" => observed_tag,
        "error" => ("source root is not a Git worktree" unless worktree)
      }.compact
    end

    # 2. No tracked or untracked patch, and no unpinned submodule or vendor tree.
    def source_cleanliness(source_root)
      unless git_worktree?(source_root)
        return {"id" => "source_cleanliness", "passed" => false, "git_available" => false, "error" => "source root is not a Git worktree"}
      end

      status = git(source_root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none")
      submodules = git(source_root, "submodule", "status", "--recursive")
      tracked = git(source_root, "ls-files", "-v", "-z")
      vendor = git(source_root, "ls-tree", "HEAD", "vendor")
      vendor_extras = git(source_root, "ls-files", "--others", "-z", "--", "vendor/")
      verified = [status, submodules, tracked, vendor, vendor_extras].all?
      dirty = status.to_s.split("\0")
      unpinned = submodules.to_s.lines(chomp: true).select { |line| line.start_with?("+", "-", "U") }
      hidden = tracked.to_s.split("\0").grep(/\A(?:S|[a-z]) /)
      vendor_tracked = vendor.to_s.match?(/\A040000 tree [0-9a-f]+\tvendor\z/)
      extras = vendor_extras.to_s.split("\0")
      {
        "id" => "source_cleanliness",
        "passed" => verified && dirty.empty? && unpinned.empty? && hidden.empty? && vendor_tracked && extras.empty?,
        "git_available" => true,
        "git_checks_complete" => verified,
        "dirty_entries" => dirty.first(20),
        "dirty_count" => dirty.length,
        "unpinned_submodules" => unpinned.first(20),
        "hidden_tracked_entries" => hidden.first(20),
        "vendor_tracked" => vendor_tracked,
        "untracked_vendor_entries" => extras.first(20)
      }
    end

    # 3. conformance.yaml digest, test count and codename uniqueness.
    def conformance_definition(source_root)
      spec = L.conformance_definition
      path = File.join(source_root, spec.fetch("path"))
      return {"id" => "conformance_definition", "passed" => false, "error" => "missing #{spec.fetch("path")}"} unless File.file?(path)

      digest = L.digest_file(path)
      require "yaml"
      document = YAML.safe_load_file(path)
      entries = (document.is_a?(Hash) ? document.values.flatten : Array(document)).grep(Hash)
      codenames = entries.filter_map { |entry| entry["codename"] }
      testnames = entries.filter_map { |entry| entry["testname"] }
      # `codename` is the unique key: upstream v1.36.2 ships 446 entries with
      # 446 distinct codenames but only 436 distinct testnames (10 human-readable
      # names are shared by different tests, e.g. "MutatingAdmissionPolicy").
      # The join onto JUnit results is by codename, so uniqueness is required
      # there and not on testname.
      {
        "id" => "conformance_definition",
        "passed" => digest == spec.fetch("sha256") &&
          entries.length == spec.fetch("test_count") &&
          codenames.length == spec.fetch("test_count") &&
          codenames.uniq.length == codenames.length,
        "expected_sha256" => spec.fetch("sha256"),
        "observed_sha256" => digest,
        "expected_test_count" => spec.fetch("test_count"),
        "observed_entry_count" => entries.length,
        "observed_codename_count" => codenames.length,
        "duplicate_codename_count" => codenames.length - codenames.uniq.length,
        "distinct_testname_count" => testnames.uniq.length,
        "shared_testnames" => testnames.tally.select { |_name, count| count > 1 }.keys.sort
      }
    rescue Psych::Exception, SystemCallError
      {"id" => "conformance_definition", "passed" => false, "error" => "cannot read the locked conformance definition"}
    end

    # 4. Runner archives match their locked checksums.
    def runner_artifacts(platform)
      entries = %w[hydrophone sonobuoy].map do |name|
        next {"runner" => name, "matches" => false, "error" => "platform is not pinned"} unless L.runner(name).fetch("artifacts").key?(platform)

        artifact = L.runner_artifact(name, platform)
        path = File.join(ROOT, "build/tools/conformance", "#{name}.tar.gz")
        observed = File.file?(path) ? L.digest_file(path) : nil
        {
          "runner" => name,
          "archive" => artifact.fetch("name"),
          "expected_sha256" => artifact.fetch("sha256"),
          "observed_sha256" => observed,
          "present" => !observed.nil?,
          "matches" => observed == artifact.fetch("sha256")
        }
      end
      {
        "id" => "runner_artifacts",
        "passed" => entries.all? { |entry| entry.fetch("matches") },
        "runners" => entries
      }
    end

    # 4–5. Validate the bytes at each locked index and platform digest.
    def image_manifests(platform, registry_client: Image::RegistryClient.method(:new))
      required = {"conformance" => L.kubernetes.fetch("conformance_image"), "sonobuoy" => L.runner("sonobuoy").fetch("image")}
      required.merge!(L.support_images)
      pending = required.transform_values { |lock| Thread.new { registry_manifest(lock, platform, registry_client) } }
      observed = pending.transform_values(&:value)
      {
        "id" => "image_manifests",
        "passed" => observed.values.all? { |entry| entry.fetch("matches") },
        "platform" => platform,
        "images" => observed
      }
    end

    def registry_manifest(lock, platform, registry_client)
      reference = L.reference_by_digest(lock)
      expected_index = lock.fetch("index_digest")
      expected_manifest = lock.fetch("platforms")[platform]
      record = {
        "reference" => reference, "tagged_reference" => lock.fetch("reference"), "matches" => false,
        "expected_index_digest" => expected_index, "expected_platform_digest" => expected_manifest
      }
      return record.merge("error" => "platform is not pinned") if expected_manifest.nil?

      os, architecture, variant = platform.split("/")
      image = Image::Reference.parse(reference)
      manifest = registry_client.call(image).manifest(image, os: os, architecture: architecture, variant: variant)
      index = manifest.index_digest&.to_s
      child = manifest.digest.to_s
      record.merge("observed_index_digest" => index, "observed_platform_digest" => child,
                   "matches" => index == expected_index && child == expected_manifest)
    rescue Image::Error => error
      record.merge("error" => error.message)
    end

    def kubeconfig_isolation(kubeconfig, oracle_kubeconfig)
      Kubeconfigs.verify(kubeconfig, oracle_kubeconfig)
    end

    # 7. Bind the exact preflight inputs to this run before any cluster lane.
    def record_inputs(directory, check, run_id:, profile:)
      cases = check.fetch("cases").to_h { |entry| [entry.fetch("id"), entry] }
      resolved = {
        "runId" => run_id, "platform" => check.fetch("platform"),
        "locked" => cases.fetch("image_manifests").fetch("images"),
        "upstream" => cases.fetch("upstream_image_inventory").fetch("images", {})
      }
      images = write_once(directory, "resolved-images.json", resolved)
      manifest = {
        "schemaVersion" => 1, "runId" => run_id, "profile" => profile,
        "sourceCommit" => cases.fetch("source_identity")["observed_head"],
        "expectedSourceCommit" => L.source_commit, "clusterId" => cases.fetch("kubeconfig_isolation")["cluster_id"],
        "clusterIdentitySource" => "kubeconfig", "resolvedImages" => images, "passed" => check.fetch("passed")
      }
      {"input_manifest" => write_once(directory, "inputs.json", manifest), "resolved_images" => images}
    end

    def write_once(directory, name, value)
      FileUtils.mkdir_p(directory)
      path = File.join(directory, name)
      File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o444) do |file|
        file.write("#{JSON.pretty_generate(value)}\n")
        file.flush
        file.fsync
      end
      {"path" => path.delete_prefix("#{ROOT}/"), "sha256" => L.digest_file(path)}
    end

    def git_worktree?(root)
      top = git(root, "rev-parse", "--show-toplevel")
      !top.nil? && File.realpath(top) == File.realpath(root)
    rescue SystemCallError
      false
    end

    def git(root, *)
      return nil unless File.directory?(root)

      command = ["git", "--no-optional-locks", "-C", root, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false"]
      out, _err, status = Open3.capture3(GIT_ENV, *command, *, binmode: true)
      out.force_encoding(Encoding::UTF_8).scrub.chomp if status.success?
    rescue SystemCallError
      nil
    end
  end
end

if $PROGRAM_NAME == __FILE__
  source_root = ENV.fetch("RUBERNETES_K8S_SOURCE", "/tmp/kubernetes-v1.36.2")
  result = Conformance::K0.run(
    source_root: source_root,
    kubeconfig: ENV.fetch("KUBECONFIG", nil),
    oracle_kubeconfig: ENV.fetch("RUBERNETES_ORACLE_KUBECONFIG", nil)
  )
  puts JSON.pretty_generate(result)
  exit(result.fetch("passed") ? 0 : 1)
end
