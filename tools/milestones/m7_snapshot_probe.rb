#!/usr/bin/env ruby
# frozen_string_literal: true

# M7 exit criterion 2 (snapshot half): the snapshot corruption corpus.  A
# real base snapshot is damaged in every way the corpus lists (bit flips in
# memory and VM state, truncation, a manifest that has been re-signed over
# corrupt bytes, a manifest bound to other artifacts, a missing file) and
# every restore must fail closed: no VMM is left running, no jail, netns,
# verity mapping, workspace or identity survives, and the ledger operation
# ends in Stopped after rollback rather than in a started state.

require_relative "m7_probe_support"

module M7SnapshotProbe
  S = M7ProbeSupport
  M = Rubernetes::Runtime::MicroVM

  module_function

  def flip_byte(path, offset)
    File.open(path, "r+b") do |file|
      file.seek(offset)
      byte = file.read(1).unpack1("C")
      file.seek(offset)
      file.write([byte ^ 0xFF].pack("C"))
    end
  end

  def resign_manifest(base)
    manifest = JSON.parse(File.read(File.join(base.directory, "manifest.json")))
    %w[mem vmstate].each do |name|
      path = File.join(base.directory, name)
      manifest["files"][name] = {"sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
    end
    File.write(File.join(base.directory, "manifest.json"), JSON.pretty_generate(manifest))
  end

  def corpus(base)
    [
      ["mem_bit_flip_middle", -> { flip_byte(base.mem_path, File.size(base.mem_path) / 2) }],
      ["vmstate_bit_flip", -> { flip_byte(base.vmstate_path, 64) }],
      ["vmstate_truncated", -> { File.truncate(base.vmstate_path, File.size(base.vmstate_path) / 2) }],
      ["mem_truncated", -> { File.truncate(base.mem_path, File.size(base.mem_path) - 4096) }],
      ["vmstate_garbage_resigned", lambda {
        File.binwrite(base.vmstate_path, "\x00" * File.size(base.vmstate_path))
        resign_manifest(base)
      }],
      ["manifest_artifact_mismatch", lambda {
        manifest = JSON.parse(File.read(File.join(base.directory, "manifest.json")))
        manifest["artifact_digest"] = "0" * 64
        File.write(File.join(base.directory, "manifest.json"), JSON.pretty_generate(manifest))
      }],
      ["mem_missing", -> { File.delete(base.mem_path) }]
    ]
  end

  def restore_attempt(runtime, network, label)
    pod = nil
    outcome = begin
      pod = S.start_pod(runtime, network, label)
      "started"
    rescue Rubernetes::Runtime::OperationFailure, Rubernetes::Runtime::Error => error
      "#{error.class.name.split("::").last}: #{error.message[0, 140]}"
    end
    [outcome, pod]
  end

  def run
    started_at = S.now
    S.require_root!
    cases = []
    runtime, root = S.build_runtime("snapshot", use_base_snapshot: true)
    network = S::ProbeNetwork.new(5)
    begin
      runtime.prepare_base!(request_id: "snapshot-base")
      pool = runtime.snapshot_pool
      pristine = pool.latest(runtime.runtime_class)
      base_id = pristine.id
      backup = File.join(root, "pristine")
      FileUtils.cp_r(pristine.directory, backup)
      outcome, pod = restore_attempt(runtime, network, "snapshot-pristine")
      session = pod && pod["session"]
      cases << {"id" => "pristine_restore", "outcome" => outcome, "restored_from" => session&.base&.id,
                "passed" => outcome == "started" && session&.base&.id == base_id}
      S.stop_pod(runtime, network, pod) if pod
      corpus(pristine).each do |name, damage|
        FileUtils.rm_rf(pristine.directory)
        FileUtils.cp_r(backup, pristine.directory)
        damage.call
        sandbox_ids_before = runtime.identity_ledger.all.length
        outcome, pod = restore_attempt(runtime, network, "snapshot-#{name}")
        vmms = `pgrep -x firecracker`.split.length
        live_identities = runtime.identity_ledger.live.length
        resources = runtime.adapter.list_resources
        S.stop_pod(runtime, network, pod) if pod
        cases << {"id" => name, "outcome" => outcome, "vmm_processes_after" => vmms, "live_identities_after" => live_identities, "resources_after" => resources,
                  "ledger_records_added" => runtime.identity_ledger.all.length - sandbox_ids_before,
                  "passed" => outcome != "started" && vmms.zero? && live_identities.zero? && resources.empty?}
      end
      FileUtils.rm_rf(pristine.directory)
      FileUtils.cp_r(backup, pristine.directory)
      outcome, pod = restore_attempt(runtime, network, "snapshot-after-corpus")
      cases << {"id" => "restore_after_corpus", "outcome" => outcome, "passed" => outcome == "started"}
      S.stop_pod(runtime, network, pod) if pod
    ensure
      network.detach_all
      S.cleanup_runtime_root(root)
    end
    S.emit(S.report(
      kind: "m7_snapshot_corruption_corpus", measurement_level: "L4", started_at: started_at, cases: cases,
      extra: {"host" => S.host_facts, "measurement_source" => "real_snapshot_files",
              "sources" => M5ProbeSupport.source_files(%w[lib/rubernetes/runtime/microvm/snapshot_pool.rb lib/rubernetes/runtime/microvm/session.rb])}
    ))
  end
end

M7SnapshotProbe.run if $PROGRAM_NAME == __FILE__
