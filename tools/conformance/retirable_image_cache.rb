# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "open3"
require "time"
require_relative "k1_evidence"

module Conformance
  # Retire only the image cache directories made by an opted-in native K1 fixture.
  class RetirableImageCache
    MARKER = "runtime/.retirable-image-cache.json"
    CGROUP_ROOT = "/sys/fs/cgroup"

    class Error < StandardError; end

    def initialize(root, descriptor)
      @root = File.expand_path(root)
      @descriptor = descriptor
      @cgroup = descriptor.fetch("cgroup_root")
      @caches = descriptor.fetch("processes").filter_map do |process|
        worker = process.fetch("name")[/\Aagent-(worker-[0-9]+)\z/, 1]
        File.join(@root, "runtime", worker, "ledger.jsonl.images") if worker
      end
    end

    def register!
      assert_fixture!
      records = @caches.to_h { |path| [File.basename(File.dirname(path)), directory_identity(path)] }
      marker = {"root" => directory_identity(@root), "cgroup" => directory_identity(@cgroup),
                "ready_at" => @descriptor.fetch("ready_at"), "kubeconfig_sha256" => kubeconfig_digest,
                "processes" => @descriptor.fetch("processes"), "caches" => records}
      File.write(marker_path, JSON.generate(marker), perm: 0o600, mode: "wx")
    end

    def retire!(receipt_path)
      verify_receipt!(receipt_path)
      yield
      marker = read_file(marker_path)
      ensure_origin!(marker)
      unless File.readlines(File.join(@cgroup, "cgroup.events"), chomp: true).include?("populated 0")
        raise Error, "fixture cgroup still contains live workloads"
      end

      sizes = @caches.filter_map do |path|
        next unless File.exist?(path) || File.symlink?(path)

        worker = File.basename(File.dirname(path))
        raise Error, "image cache identity changed for #{worker}" unless directory_identity(path) == marker.fetch("caches").fetch(worker)

        [path, allocated_bytes(path)]
      end.to_h
      assert_unmounted!
      sizes.each_key { |path| FileUtils.remove_entry_secure(path) }
      File.unlink(marker_path)
      {"directories" => sizes.keys, "allocated_bytes" => sizes.values.sum}
    end

    private

    def verify_receipt!(path)
      assert_fixture!
      raise Error, "fixture did not opt in to image cache retirement" unless File.file?(marker_path)

      ensure_origin!(read_file(marker_path))

      receipt = read_file(path)
      lane = receipt.fetch("lanes").find { |entry| entry["lane"] == "K1" }
      raise Error, "image cache retirement requires a successful full K1 result for this fixture" unless successful?(receipt, lane)

      output = File.dirname(path)
      raise Error, "K1 evidence must be outside the fixture runtime directory" if output.start_with?("#{@root}/runtime/")

      command = verified_artifact!(receipt, File.join(output, "k1/hydrophone-command.json"))
      verified_artifact!(receipt, File.join(output, "k1/hydrophone/junit_01.xml"))
      execution = read_file(command)
      arguments = execution.fetch("command")
      kubeconfig_index = arguments.index("--kubeconfig")
      if execution["exit_status"] != 0 || execution["timed_out"] || !arguments.include?("--conformance") ||
         !kubeconfig_index || arguments[kubeconfig_index + 1] != @descriptor["kubeconfig"]
        raise Error, "K1 receipt does not record a successful run against this fixture kubeconfig"
      end
    end

    def marker_path = File.join(@root, MARKER)

    def assert_fixture!
      scope = File.dirname(@root)
      directory_identity(scope)
      directory_identity(@root)
      directory_identity(File.join(@root, "runtime"))
      unless @descriptor["kind"] == "conformance_cluster" && @descriptor["root"] == @root &&
             @descriptor["isolated_worker_networks"] == true &&
             @cgroup.start_with?("#{CGROUP_ROOT}/") && !@caches.empty?
        raise Error, "image cache retirement requires an isolated native fixture with its own cgroup"
      end

      @caches.each { |path| directory_identity(File.dirname(path)) }
    end

    def directory_identity(path)
      stat = File.lstat(path)
      unless stat.directory? && stat.uid == Process.euid && stat.mode.nobits?(0o022) && File.realpath(path) == path
        raise Error, "unowned or noncanonical fixture directory #{path}"
      end

      [stat.dev, stat.ino]
    end

    def ensure_origin!(marker)
      unless marker["root"] == directory_identity(@root) && marker["cgroup"] == directory_identity(@cgroup) &&
             marker["ready_at"] == @descriptor["ready_at"] && marker["kubeconfig_sha256"] == kubeconfig_digest &&
             marker["processes"] == @descriptor["processes"]
        raise Error, "recorded cache owner is not this fixture"
      end
    end

    def successful?(receipt, lane)
      receipt["profile"] == @descriptor.dig("profile", "name") && receipt["sourceCommit"] == Lock.source_commit &&
        Time.iso8601(receipt.fetch("startedAt")) >= Time.iso8601(@descriptor.fetch("ready_at")) &&
        receipt.dig("summary", "passed") == true && lane&.fetch("status") == "COMPLETE" && lane["passed"] == true &&
        K1Evidence.complete?(lane.fetch("summary"), lane.fetch("codenames"), expected: Lock.conformance_definition.fetch("test_count"))
    end

    def kubeconfig_digest
      path = File.join(@root, "kubeconfig")
      raise Error, "fixture kubeconfig points outside its cluster directory" unless @descriptor["kubeconfig"] == path

      require_regular!(path)
      Digest::SHA256.file(path).hexdigest
    end

    def read_file(path)
      require_regular!(path)
      JSON.parse(File.binread(path))
    end

    def require_regular!(path)
      return if File.lstat(path).file? && File.realpath(path) == path

      raise Error, "expected a regular evidence file at #{path}"
    end

    def verified_artifact!(receipt, path)
      require_regular!(path)
      artifact = receipt.fetch("artifacts").find { |entry| File.expand_path(entry.fetch("path"), Lock::ROOT) == path }
      raise Error, "K1 evidence digest does not match #{path}" unless artifact && Digest::SHA256.file(path).hexdigest == artifact.fetch("sha256")

      path
    end

    def allocated_bytes(path)
      output, error, status = Open3.capture3("du", "-sx", "-B1", "--", path)
      raise Error, "unable to measure cache #{path}: #{error.strip}" unless status.success?

      Integer(output.split.first)
    end

    def assert_unmounted!
      namespaces = {}
      ["/proc/self/mountinfo", *Dir["/proc/[0-9]*/mountinfo"]].each do |path|
        namespace = File.readlink(File.join(File.dirname(path), "ns/mnt"))
        next if namespaces[namespace]

        File.foreach(path) do |line|
          decoded = line.gsub(/\\([0-7]{3})/) { ::Regexp.last_match(1).to_i(8).chr }
          raise Error, "a mount still references the fixture image cache" if @caches.any? { |cache| decoded.include?(cache) }
        end
        namespaces[namespace] = true
      rescue Errno::ENOENT, Errno::ESRCH
        next
      end
    end
  end
end
