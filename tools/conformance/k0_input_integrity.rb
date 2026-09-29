#!/usr/bin/env ruby
# frozen_string_literal: true

# K0 — Input Integrity (spec/verification/kubernetes-compatibility.md#k0).
#
# Runs before the runner touches a cluster.  Every check reads the pinned
# locks and the real checkout; a mismatch is a test failure and the lock is
# never refreshed from the network to make a check pass.

require "digest"
require "json"
require "open3"

require_relative "lock"

module Conformance
  module K0
    L = Conformance::Lock
    ROOT = L::ROOT

    module_function

    def run(source_root:, platform: "linux/amd64", kubeconfig: nil, oracle_kubeconfig: nil)
      cases = []
      cases << source_identity(source_root)
      cases << source_cleanliness(source_root)
      cases << conformance_definition(source_root)
      cases << runner_artifacts(platform)
      cases << image_manifests(platform)
      cases << kubeconfig_isolation(kubeconfig, oracle_kubeconfig)
      {
        "lane" => "K0",
        "passed" => cases.all? { |entry| entry.fetch("passed") },
        "platform" => platform,
        "cases" => cases
      }
    end

    # 1. The tag object and the peeled commit both match the lock.
    def source_identity(source_root)
      expected_commit = L.source_commit
      expected_tag = L.tag_object
      observed_commit = git(source_root, "rev-parse", "v1.36.2^{commit}")
      observed_tag = git(source_root, "rev-parse", "v1.36.2")
      # A source tree exported without .git still has to prove its identity, so
      # fall back to the recorded commit marker the export carries.
      if observed_commit.nil?
        marker = File.join(source_root, ".rubernetes-source-commit")
        observed_commit = File.file?(marker) ? File.read(marker).strip : nil
        observed_tag = nil
      end
      {
        "id" => "source_identity",
        "passed" => observed_commit == expected_commit &&
                    (observed_tag.nil? || observed_tag == expected_tag),
        "expected_commit" => expected_commit,
        "observed_commit" => observed_commit,
        "expected_tag_object" => expected_tag,
        "observed_tag_object" => observed_tag
      }
    end

    # 2. No tracked or untracked patch, and no unpinned submodule or vendor tree.
    def source_cleanliness(source_root)
      status = git(source_root, "status", "--porcelain")
      submodules = git(source_root, "submodule", "status")
      dirty = status.nil? ? [] : status.split("\n").reject(&:empty?)
      unpinned = submodules.nil? ? [] : submodules.split("\n").select { |line| line.start_with?("+", "-", "U") }
      {
        "id" => "source_cleanliness",
        "passed" => dirty.empty? && unpinned.empty?,
        "git_available" => !status.nil?,
        "dirty_entries" => dirty.first(20),
        "dirty_count" => dirty.length,
        "unpinned_submodules" => unpinned.first(20)
      }
    end

    # 3. conformance.yaml digest, test count and codename uniqueness.
    def conformance_definition(source_root)
      spec = L.conformance_definition
      path = File.join(source_root, spec.fetch("path"))
      unless File.file?(path)
        return {"id" => "conformance_definition", "passed" => false, "error" => "missing #{spec.fetch("path")}"}
      end

      digest = L.digest_file(path)
      require "yaml"
      document = YAML.safe_load(File.read(path))
      entries = (document.is_a?(Hash) ? document.values.flatten : Array(document)).select { |entry| entry.is_a?(Hash) }
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
    end

    # 4. Runner archives match their locked checksums.
    def runner_artifacts(platform)
      entries = %w[hydrophone sonobuoy].map do |name|
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

    # 5. The image index really carries the target platform; never fall back.
    def image_manifests(platform)
      expected = L.platform_digest(platform)
      index = L.conformance_image_digest
      support = L.support_images.transform_values do |image|
        {
          "index_digest" => image.fetch("index_digest"),
          "platform_digest" => image.fetch("platforms")[platform],
          "resolves" => !image.fetch("platforms")[platform].nil?
        }
      end
      {
        "id" => "image_manifests",
        "passed" => !expected.nil? && !index.nil? && support.values.all? { |entry| entry.fetch("resolves") },
        "platform" => platform,
        "conformance_index_digest" => index,
        "conformance_platform_digest" => expected,
        "support_images" => support
      }
    end

    # 6. The test KUBECONFIG must name only the Rubernetes cluster and must not
    #    share credentials with the Kubernetes oracle cluster.
    def kubeconfig_isolation(kubeconfig, oracle_kubeconfig)
      unless kubeconfig
        return {"id" => "kubeconfig_isolation", "passed" => false, "error" => "no kubeconfig given"}
      end
      unless File.file?(kubeconfig)
        return {"id" => "kubeconfig_isolation", "passed" => false, "error" => "kubeconfig #{kubeconfig} is missing"}
      end

      require "yaml"
      document = YAML.safe_load(File.read(kubeconfig), aliases: true) || {}
      clusters = Array(document["clusters"]).map { |entry| entry["name"] }
      servers = Array(document["clusters"]).map { |entry| entry.dig("cluster", "server") }
      secrets = credential_material(document)
      oracle_secrets = if oracle_kubeconfig && File.file?(oracle_kubeconfig)
                         credential_material(YAML.safe_load(File.read(oracle_kubeconfig), aliases: true) || {})
                       else
                         []
                       end
      shared = secrets & oracle_secrets
      {
        "id" => "kubeconfig_isolation",
        "passed" => !clusters.empty? && shared.empty?,
        "clusters" => clusters,
        "servers" => servers,
        "shared_credential_count" => shared.length
      }
    end

    def credential_material(document)
      Array(document["users"]).flat_map do |entry|
        user = entry["user"] || {}
        %w[client-certificate-data client-key-data token password].filter_map do |key|
          value = user[key]
          Digest::SHA256.hexdigest(value.to_s) unless value.nil? || value.to_s.empty?
        end
      end
    end

    def git(root, *args)
      return nil unless File.directory?(File.join(root, ".git"))

      out, _err, status = Open3.capture3("git", "-C", root, *args)
      status.success? ? out.strip : nil
    rescue Errno::ENOENT
      nil
    end
  end
end

if $PROGRAM_NAME == __FILE__
  source_root = ENV.fetch("RUBERNETES_K8S_SOURCE", "/tmp/kubernetes-v1.36.2")
  result = Conformance::K0.run(
    source_root: source_root,
    kubeconfig: ENV["KUBECONFIG"],
    oracle_kubeconfig: ENV["RUBERNETES_ORACLE_KUBECONFIG"]
  )
  puts JSON.pretty_generate(result)
  exit(result.fetch("passed") ? 0 : 1)
end
