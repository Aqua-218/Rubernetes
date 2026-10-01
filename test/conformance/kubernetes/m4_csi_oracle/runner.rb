#!/usr/bin/env ruby
# frozen_string_literal: true

# External CSI oracle runner for the M4 volume evidence.
#
# It builds and starts an independent CSI plugin (plugin/main.go, written
# against the pinned container-storage-interface spec v1.9.0 and speaking
# gRPC over a Unix socket with real bind-mount effects), then drives the
# production CSI client (Rubernetes::Volume::CSIBridge over CSIUDSClient)
# through the required controller/node operations.  For every operation two
# observations are produced independently and compared content-bound:
#
#   expected - the plugin's journal: the request it received, the gRPC status
#              it returned, and its own /proc/self/mountinfo readback;
#   actual   - the production client's view: the arguments it sent, the
#              response it decoded, and this runner's mountinfo readback.
#
# The whole runner executes inside a private mount namespace so the plugin's
# bind mounts never reach the host mount table.
#
# Request (stdin): {"kubernetes_version", "source_commit", "required_operations"}.

require "digest"
require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "socket"
require "time"
require "tmpdir"

ROOT = File.expand_path("../../../..", __dir__)
$LOAD_PATH.unshift(File.join(ROOT, "lib")) unless $LOAD_PATH.include?(File.join(ROOT, "lib"))
require_relative "../m4_volume_observation/observer_support"

module M4CSIOracleRunner
  RUNNER_PATH = File.expand_path(__FILE__)
  PLUGIN_DIR = File.join(__dir__, "plugin")
  BUILD_DIR = File.join(ROOT, "build/tools/m4-csi-oracle")
  IMPLEMENTATION = "independent Go CSI plugin (container-storage-interface/spec v1.9.0, gRPC over UDS, bind-mount effects) driven by the production " \
                   "CSIBridge/CSIUDSClient"
  CSI_SPEC_VERSION = "1.9.0"
  NODE = "m4-oracle-node"
  DEFAULT_OPERATIONS = %w[
    GetPluginInfo CreateVolume DeleteVolume ControllerPublishVolume ControllerUnpublishVolume
    NodeStageVolume NodeUnstageVolume NodePublishVolume NodeUnpublishVolume NodeGetVolumeStats
  ].freeze

  module_function

  def plugin_source_sha256
    files = Dir.glob(File.join(PLUGIN_DIR, "*")).select { |path| File.file?(path) }.sort
    Digest::SHA256.hexdigest(files.map { |path| "#{File.basename(path)}\0#{Digest::SHA256.file(path).hexdigest}\n" }.join)
  end

  # The plugin binary is content-addressed by its Go sources and module
  # lock; it is rebuilt only when they change.
  def build_plugin!
    source_sha = plugin_source_sha256
    binary = File.join(BUILD_DIR, "plugin-#{source_sha[0, 16]}")
    return [binary, source_sha, JSON.parse(File.read("#{binary}.json"))] if File.executable?(binary) && File.file?("#{binary}.json")

    FileUtils.mkdir_p(BUILD_DIR)
    environment = {"GOTOOLCHAIN" => "auto", "GOWORK" => "off", "CGO_ENABLED" => "0", "GOFLAGS" => "-mod=mod"}
    stdout, stderr, status = Open3.capture3(environment, "go", "build", "-trimpath", "-o", binary, ".", chdir: PLUGIN_DIR)
    raise "go build of the CSI oracle plugin failed: #{stderr.strip}\n#{stdout}" unless status.success?

    version, = Open3.capture3(environment, "go", "version", chdir: PLUGIN_DIR)
    record = {"source_sha256" => source_sha, "binary_sha256" => Digest::SHA256.file(binary).hexdigest,
              "go_version" => version.strip, "built_at" => M4ObserverSupport.iso8601_now,
              "go_mod_sha256" => Digest::SHA256.file(File.join(PLUGIN_DIR, "go.mod")).hexdigest,
              "go_sum_sha256" => Digest::SHA256.file(File.join(PLUGIN_DIR, "go.sum")).hexdigest,
              "csi_spec_version" => CSI_SPEC_VERSION}
    File.write("#{binary}.json", JSON.generate(record))
    [binary, source_sha, record]
  end

  def mount_readback(target)
    entry = M4ObserverSupport.mountinfo_entries(Process.pid).find { |candidate| candidate.fetch("target") == File.expand_path(target) }
    return {"target" => File.expand_path(target), "mounted" => false} unless entry

    {"target" => entry.fetch("target"), "mounted" => true, "mountId" => entry.fetch("mountId"), "deviceId" => entry.fetch("deviceId"),
     "root" => entry.fetch("root"), "filesystem" => entry.fetch("filesystem"), "readonly" => entry.fetch("readonly")}
  end

  class Session
    attr_reader :errors, :comparisons, :journal

    def initialize(request, plugin_binary:, plugin_record:)
      @request = request
      @plugin_binary = plugin_binary
      @plugin_record = plugin_record
      @errors = []
      @comparisons = []
      @journal = []
      @client_log = []
    end

    def run
      Dir.mktmpdir("rubernetes-m4-csi-oracle") do |directory|
        @directory = directory
        socket = File.join(directory, "csi.sock")
        state_dir = File.join(directory, "state")
        journal_path = File.join(directory, "journal.jsonl")
        FileUtils.mkdir_p(state_dir)
        start_plugin!(socket, state_dir, journal_path)
        begin
          drive_client!(socket, directory)
        ensure
          stop_plugin!
        end
        @journal = File.file?(journal_path) ? File.readlines(journal_path, chomp: true).map { |line| JSON.parse(line) } : []
        compare!
      end
      self
    end

    private

    def start_plugin!(socket, state_dir, journal_path)
      stdout_read, stdout_write = IO.pipe
      @plugin_stderr = File.join(@directory, "plugin.stderr")
      @plugin_pid = Process.spawn(@plugin_binary, "--endpoint", socket, "--state-dir", state_dir, "--journal", journal_path,
                                  in: File::NULL, out: stdout_write, err: @plugin_stderr)
      stdout_write.close
      ready = M4ObserverSupport.wait_for(timeout: 15) do
        stdout_read.wait_readable(0.05) ? stdout_read.gets : nil
      end
      raise "CSI oracle plugin did not report readiness: #{File.read(@plugin_stderr) if File.file?(@plugin_stderr)}" unless ready

      @plugin_ready = JSON.parse(ready)
      M4ObserverSupport.wait_for(timeout: 10) { File.socket?(socket) } || raise("CSI oracle plugin socket did not appear")
      @plugin_identity = M4ObserverSupport.process_identity(@plugin_pid)
      stdout_read.close
    end

    def stop_plugin!
      return unless @plugin_pid

      begin
        Process.kill("TERM", @plugin_pid)
        Process.waitpid(@plugin_pid)
      rescue Errno::ESRCH, Errno::ECHILD
        nil
      end
    end

    # Every production call is recorded with the exact arguments handed to
    # the bridge and the decoded response, then the runner reads the kernel
    # mount table itself (same mount namespace as the plugin).
    def call(operation, kernel_target: nil)
      started = M4ObserverSupport.iso8601_now
      response = yield
      value = response.respond_to?(:to_h) ? response.to_h : response
      kernel = kernel_target ? M4CSIOracleRunner.mount_readback(kernel_target) : nil
      @client_log << {"operation" => operation, "started_at" => started, "response" => M4ObserverSupport.canonical_value(value),
                      "status" => "OK", "kernel" => kernel}
      value
    rescue StandardError => error
      @client_log << {"operation" => operation, "started_at" => started, "status" => "ERROR", "error" => "#{error.class}: #{error.message}",
                      "kernel" => kernel_target ? M4CSIOracleRunner.mount_readback(kernel_target) : nil}
      raise
    end

    def drive_client!(socket, directory)
      require "rubernetes/volume"
      bridge = Rubernetes::Volume::CSIBridge.new(socket: socket, timeout: 15)
      stage_path = File.join(directory, "staging")
      target_path = File.join(directory, "target")
      FileUtils.mkdir_p(stage_path)
      FileUtils.mkdir_p(target_path)
      volume_name = "m4-csi-oracle-volume"
      identity = call("GetPluginInfo") { bridge.identity }
      @plugin_name = identity.respond_to?(:name) ? identity.name : identity.to_h["name"]
      created = call("CreateVolume") do
        bridge.create_volume({"id" => volume_name, "name" => volume_name, "capacityBytes" => 4 * 1024 * 1024,
                              "accessModes" => ["ReadWriteOnce"]}, token: "m4-csi-oracle-create")
      end
      @volume_id = created["volumeId"] || created["volume_id"] || created.dig("volume", "volumeId")
      raise "CreateVolume returned no volume id: #{created.inspect}" unless @volume_id.is_a?(String) && !@volume_id.empty?

      call("ControllerPublishVolume") do
        bridge.publish(@volume_id, NODE, token: "m4-csi-oracle-attach", context: {"accessModes" => ["ReadWriteOnce"]})
      end
      call("NodeStageVolume", kernel_target: stage_path) do
        bridge.stage(@volume_id, stage_path, token: "m4-csi-oracle-stage", readonly: false, context: {"accessModes" => ["ReadWriteOnce"]})
      end
      call("NodePublishVolume", kernel_target: target_path) do
        bridge.publish_node(@volume_id, stage_path, target_path, token: "m4-csi-oracle-publish", readonly: false,
                                                                 context: {"accessModes" => ["ReadWriteOnce"]})
      end
      File.binwrite(File.join(target_path, "payload"), "m4-csi-oracle-payload\n" * 64)
      @payload_visible_in_volume = Dir.glob(File.join(directory, "state", "volumes", "*", "payload")).any?
      call("NodeGetVolumeStats", kernel_target: target_path) { bridge.stats(@volume_id, path: target_path) }
      call("NodeUnpublishVolume", kernel_target: target_path) do
        bridge.unpublish_node(@volume_id, target_path, token: "m4-csi-oracle-unpublish")
      end
      call("NodeUnstageVolume", kernel_target: stage_path) { bridge.unstage(@volume_id, stage_path, token: "m4-csi-oracle-unstage") }
      call("ControllerUnpublishVolume") { bridge.unpublish(@volume_id, NODE, token: "m4-csi-oracle-detach") }
      call("DeleteVolume") { bridge.delete_volume(@volume_id, token: "m4-csi-oracle-delete") }
      @stage_path = stage_path
      @target_path = target_path
    rescue StandardError => error
      @errors << "production CSI client lifecycle failed: #{error.class}: #{error.message}"
    end

    # Both sides are reduced to the same observable shape so a content-bound
    # comparison proves the client and the plugin agree on what happened.
    def compare!
      required = Array(@request["required_operations"]).empty? ? DEFAULT_OPERATIONS : Array(@request["required_operations"])
      required.each do |operation|
        plugin_entries = @journal.select { |entry| entry["operation"] == operation }
        client_entries = @client_log.select { |entry| entry["operation"] == operation }
        expected = observable_from_plugin(operation, plugin_entries.last)
        actual = observable_from_client(operation, client_entries.last)
        comparison = M4ObserverSupport.comparison(operation, expected, actual,
                                                  "operation" => operation, "measurement_source" => "external_csi_plugin_journal",
                                                  "plugin_sequence" => plugin_entries.last && plugin_entries.last["sequence"],
                                                  "plugin_journal" => plugin_entries.last, "client_record" => client_entries.last)
        @errors << "operation #{operation} differs between the plugin journal and the production client" unless comparison["passed"]
        @comparisons << comparison
      end
      @errors << "payload written through the published target did not reach the plugin volume" unless @payload_visible_in_volume
      @errors << "plugin name is not the oracle plugin" unless @plugin_name == "m4-oracle.csi.rubernetes.dev"
    end

    def observable_from_plugin(operation, entry)
      return {"operation" => operation, "observed" => false} unless entry.is_a?(Hash)

      request = entry["request"].is_a?(Hash) ? entry["request"] : {}
      kernel = entry["kernel"].is_a?(Hash) ? entry["kernel"] : nil
      kernel = kernel["mount"] if kernel && kernel.key?("mount") && kernel["mount"].is_a?(Hash)
      base = {"operation" => operation, "status" => entry["status_code"] == "OK" ? "OK" : "ERROR"}
      case operation
      when "GetPluginInfo"
        base.merge("plugin_name" => entry.dig("response", "name"))
      when "CreateVolume"
        base.merge("volume_name" => request["name"], "volume_id" => entry.dig("response", "volume", "volume_id"),
                   "capacity_bytes" => Integer(entry.dig("response", "volume", "capacity_bytes") || 0))
      when "DeleteVolume", "ControllerUnpublishVolume"
        base.merge("volume_id" => request["volume_id"])
      when "ControllerPublishVolume"
        base.merge("volume_id" => request["volume_id"], "node_id" => request["node_id"])
      when "NodeStageVolume", "NodeUnstageVolume"
        base.merge("volume_id" => request["volume_id"], "target" => request["staging_target_path"],
                   "mounted" => kernel ? kernel["mounted"] == true : nil, "mount_id" => kernel && kernel["mountId"].to_s,
                   "device_id" => kernel && kernel["deviceId"].to_s, "readonly" => kernel && kernel["readonly"] == true)
      when "NodePublishVolume", "NodeUnpublishVolume"
        base.merge("volume_id" => request["volume_id"], "target" => request["target_path"],
                   "mounted" => kernel ? kernel["mounted"] == true : nil, "mount_id" => kernel && kernel["mountId"].to_s,
                   "device_id" => kernel && kernel["deviceId"].to_s, "readonly" => kernel && kernel["readonly"] == true)
      when "NodeGetVolumeStats"
        usage = Array(entry.dig("response", "usage")).find { |item| item["unit"] == "BYTES" } || {}
        base.merge("volume_id" => request["volume_id"], "target" => request["volume_path"],
                   "mounted" => kernel ? kernel["mounted"] == true : nil, "mount_id" => kernel && kernel["mountId"].to_s,
                   "total_bytes" => Integer(usage["total"] || 0))
      else
        base
      end
    end

    def observable_from_client(operation, entry)
      return {"operation" => operation, "observed" => false} unless entry.is_a?(Hash)

      response = entry["response"].is_a?(Hash) ? entry["response"] : {}
      kernel = entry["kernel"].is_a?(Hash) ? entry["kernel"] : nil
      base = {"operation" => operation, "status" => entry["status"] == "OK" ? "OK" : "ERROR"}
      case operation
      when "GetPluginInfo"
        base.merge("plugin_name" => response["name"])
      when "CreateVolume"
        base.merge("volume_name" => "m4-csi-oracle-volume", "volume_id" => @volume_id,
                   "capacity_bytes" => Integer(response["capacityBytes"] || response["capacity_bytes"] || 0))
      when "DeleteVolume", "ControllerUnpublishVolume"
        base.merge("volume_id" => @volume_id)
      when "ControllerPublishVolume"
        base.merge("volume_id" => @volume_id, "node_id" => NODE)
      when "NodeStageVolume", "NodeUnstageVolume"
        base.merge("volume_id" => @volume_id, "target" => @stage_path,
                   "mounted" => kernel ? kernel["mounted"] == true : nil, "mount_id" => kernel && kernel["mountId"].to_s,
                   "device_id" => kernel && kernel["deviceId"].to_s, "readonly" => kernel && kernel["readonly"] == true)
      when "NodePublishVolume", "NodeUnpublishVolume"
        base.merge("volume_id" => @volume_id, "target" => @target_path,
                   "mounted" => kernel ? kernel["mounted"] == true : nil, "mount_id" => kernel && kernel["mountId"].to_s,
                   "device_id" => kernel && kernel["deviceId"].to_s, "readonly" => kernel && kernel["readonly"] == true)
      when "NodeGetVolumeStats"
        base.merge("volume_id" => @volume_id, "target" => @target_path,
                   "mounted" => kernel ? kernel["mounted"] == true : nil, "mount_id" => kernel && kernel["mountId"].to_s,
                   "total_bytes" => Integer(response["capacityBytes"] || response["capacity_bytes"] || response["totalBytes"] || 0))
      else
        base
      end
    end

    public

    def document(request, started_at, plugin_binary:, plugin_source_sha:, plugin_record:)
      finished_at = M4ObserverSupport.iso8601_now
      provenance = M4ObserverSupport.runner_provenance(RUNNER_PATH, implementation: IMPLEMENTATION, started_at: started_at,
                                                                    finished_at: finished_at)
      {
        "schema_version" => 1, "suite" => "m4-csi-oracle", "executed" => true,
        "runner" => provenance, "runner_sha256" => provenance.fetch("runner_sha256"),
        "request_sha256" => M4ObserverSupport.digest(request),
        "kubernetes_version" => request["kubernetes_version"], "source_commit" => request["source_commit"],
        "plugin" => {"name" => "m4-oracle.csi.rubernetes.dev", "binary" => plugin_binary.delete_prefix("#{ROOT}/"),
                     "binary_sha256" => Digest::SHA256.file(plugin_binary).hexdigest, "source_sha256" => plugin_source_sha,
                     "source_directory" => PLUGIN_DIR.delete_prefix("#{ROOT}/"), "csi_spec_version" => CSI_SPEC_VERSION,
                     "build" => plugin_record, "ready" => @plugin_ready, "process" => @plugin_identity},
        "mount_namespace_inode" => File.stat("/proc/self/ns/mnt").ino,
        "comparisons" => @comparisons, "operations" => @comparisons.map { |entry| entry["operation"] },
        "comparison_count" => @comparisons.length, "journal" => @journal, "client_log" => @client_log,
        "kernel_backed" => true, "measurement_source" => "external_csi_plugin",
        "errors" => @errors, "failure_count" => @errors.length, "passed" => @errors.empty?
      }
    end
  end

  def main
    raw = $stdin.read.to_s
    request = raw.strip.empty? ? {} : JSON.parse(raw)
    request = {} unless request.is_a?(Hash)
    unless ENV["RUBERNETES_M4_CSI_ORACLE_PRIVATE_MOUNTS"] == "1"
      # Re-exec inside a private mount namespace so plugin bind mounts stay
      # invisible to the host; the child inherits stdin content via argv.
      environment = ENV.to_h.merge("RUBERNETES_M4_CSI_ORACLE_PRIVATE_MOUNTS" => "1",
                                   "RUBERNETES_M4_CSI_ORACLE_REQUEST" => JSON.generate(request))
      exec(environment, "unshare", "--mount", "--propagation", "private", "--", RbConfig.ruby, RUNNER_PATH, *ARGV)
    end
    request = JSON.parse(ENV.fetch("RUBERNETES_M4_CSI_ORACLE_REQUEST", "{}")) if request.empty?
    started_at = M4ObserverSupport.iso8601_now
    binary, source_sha, record = build_plugin!
    session = Session.new(request, plugin_binary: binary, plugin_record: record).run
    document = session.document(request, started_at, plugin_binary: binary, plugin_source_sha: source_sha, plugin_record: record)
    document["document_sha256"] = M4ObserverSupport.digest(document)
    puts JSON.generate(document)
    exit(document["passed"] ? 0 : 1)
  rescue StandardError => error
    warn "#{error.class}: #{error.message}"
    warn error.backtrace.first(10).join("\n")
    exit 2
  end
end

M4CSIOracleRunner.main if $PROGRAM_NAME == __FILE__
