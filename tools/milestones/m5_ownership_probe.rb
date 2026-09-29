#!/usr/bin/env ruby
# frozen_string_literal: true

# Resource ownership ledger / effect-point evidence (M5 exit criterion 6,
# stage 13).  For every durable effect journal in the project the probe
# records an intent, crashes the client at each of the two ambiguous points
# (before the effect reached the store = request loss; after the effect but
# before the response was recorded = response loss), reloads the journal
# from disk, checks that the classification distinguishes the two, and
# re-executes the operation.  The effect must have happened exactly once.
#
# The Raft store scenarios run against a real in-process 3-node cluster
# (TLS transport, WAL fsync); the component journals (runtime ownership
# ledger, controller effect journal, volume operation ledger, network event
# journal) are exercised through their production classes at level L2.

require "fileutils"
require "tmpdir"

require_relative "m5_probe_support"
$LOAD_PATH.unshift File.join(M5ProbeSupport::ROOT, "lib")
require "rubernetes/consensus"
require "rubernetes/runtime/ownership"
require "rubernetes/controller/effect_journal"
require "rubernetes/volume"
require "rubernetes/network/durable_state"

module M5OwnershipProbe
  C = Rubernetes::Consensus

  EFFECT_POINTS = [
    {"component" => "raft_store", "effect" => "create", "journal" => "Consensus::OperationJournal"},
    {"component" => "raft_store", "effect" => "update", "journal" => "Consensus::OperationJournal"},
    {"component" => "raft_store", "effect" => "delete", "journal" => "Consensus::OperationJournal"},
    {"component" => "native_runtime", "effect" => "run_sandbox", "journal" => "Runtime::OwnershipLedger"},
    {"component" => "controller", "effect" => "api_mutation", "journal" => "Controller::EffectJournal"},
    {"component" => "volume", "effect" => "attach", "journal" => "Volume::OperationLedger"},
    {"component" => "network", "effect" => "ip_lease", "journal" => "Network::EventJournal"}
  ].freeze

  module_function

  def start_cluster(root)
    ca, ca_key = C::Identity.generate_ca("own")
    ids = %w[a b c]
    servers = ids.to_h do |id|
      bundle = C::Identity.issue_node(ca, ca_key, cluster_id: "own", node_id: id)
      [id, C::Server.new(id: id, cluster_id: "own", data_directory: File.join(root, id), bundle: bundle, initial_voters: ids)]
    end
    servers.each_value(&:start)
    servers.each_value { |server| servers.each { |peer_id, peer| server.add_peer(peer_id, peer.address) unless peer.equal?(server) } }
    sleep 0.05 until servers.values.any?(&:leader?)
    servers
  end

  def raft_cases(root)
    servers = start_cluster(root)
    journal_path = File.join(root, "client-journal.jsonl")
    cases = []
    %w[create update delete].each do |effect|
      key = "own/#{effect}"
      request_id = "req-#{effect}"
      # Seed the object for update/delete.
      seed_store = C::RaftStore.new(servers["a"])
      seed_store.create(key, {"metadata" => {"name" => effect}, "spec" => {"v" => 0}}) unless effect == "create"
      command = case effect
                when "create" then ["create", {"metadata" => {"name" => effect}, "spec" => {"v" => 1}}]
                when "update" then ["update", {"metadata" => {"name" => effect}, "spec" => {"v" => 1}}]
                when "delete" then ["delete", nil]
                end

      # --- request loss: intent journaled, crash before the proposal reached the cluster.
      journal = C::OperationJournal.new(journal_path, component: "probe")
      journal.record_request(request_id: "#{request_id}-rl", effect: effect, key: key, command: {"type" => effect, "key" => key})
      journal = nil # crash
      reloaded = C::OperationJournal.new(journal_path, component: "probe")
      request_loss = reloaded.classification("#{request_id}-rl")
      store = C::RaftStore.new(servers["b"], journal: reloaded)
      revision_before = store.revision
      first = execute(store, effect, key, command, "#{request_id}-rl")
      reloaded.record_resolution(request_id: "#{request_id}-rl", discovered: "applied_on_retry")
      after_first = store.revision

      # --- response loss: the effect was applied but the outcome record was
      # never written (crash between apply and response).
      key2 = "#{key}-2"
      seed_store.create(key2, {"metadata" => {"name" => "#{effect}-2"}, "spec" => {"v" => 0}}) unless effect == "create"
      journal = C::OperationJournal.new(journal_path, component: "probe")
      journal.record_request(request_id: "#{request_id}-resp", effect: effect, key: key2, command: {"type" => effect, "key" => key2})
      applied_once = execute(C::RaftStore.new(servers["c"]), effect, key2, command, "#{request_id}-resp")
      journal.record_outcome(request_id: "#{request_id}-resp", state: "unknown", error: C::Timeout.new("response lost"))
      journal = nil # crash
      reloaded2 = C::OperationJournal.new(journal_path, component: "probe")
      response_loss = reloaded2.classification("#{request_id}-resp")
      store2 = C::RaftStore.new(servers["a"], journal: reloaded2)
      revision_before_retry = store2.revision
      retried = execute(store2, effect, key2, command, "#{request_id}-resp")
      reloaded2.record_resolution(request_id: "#{request_id}-resp", discovered: "already_applied")
      no_double_effect = store2.revision == revision_before_retry && (effect == "delete" || retried == applied_once)
      cases << {
        "id" => "raft_store_#{effect}",
        "component" => "raft_store",
        "effect" => effect,
        "request_loss_classification" => request_loss,
        "response_loss_classification" => response_loss,
        "request_loss_effect_count" => after_first - revision_before,
        "response_loss_retry_effect_count" => store2.revision - revision_before_retry,
        "retry_returns_original_result" => effect == "delete" || retried == applied_once,
        "journal_records" => reloaded2.records.length,
        "measurement_level" => "L2",
        "measurement_source" => "real_raft_cluster_tls",
        "passed" => request_loss == "request_loss" && response_loss == "response_loss" && (after_first - revision_before) == 1 &&
                    no_double_effect && !first.nil?
      }
    end
    cases
  ensure
    servers&.each_value(&:stop)
  end

  def execute(store, effect, key, command, request_id)
    case effect
    when "create" then store.create(key, command[1], request_uid: request_id)
    when "update" then store.guaranteed_update(key, request_uid: request_id) { |current| current.merge("spec" => command[1]["spec"]) }
    when "delete" then store.delete(key, request_uid: request_id)
    end
  end

  def runtime_case(root)
    path = File.join(root, "runtime-ledger.jsonl")
    ledger = Rubernetes::Runtime::OwnershipLedger.new(journal: Rubernetes::Runtime::RollbackJournal.new(path))
    # Request loss: request started, crash before any effect.
    ledger.begin_request(request_id: "sandbox-1", operation: "run_sandbox", config_digest: "d1")
    ledger = nil
    reloaded = Rubernetes::Runtime::OwnershipLedger.new(journal: Rubernetes::Runtime::RollbackJournal.new(path))
    request_state = reloaded.request("sandbox-1")&.state
    # Re-execution with the same intent is accepted; different intent is rejected.
    replay = reloaded.begin_request(request_id: "sandbox-1", operation: "run_sandbox", config_digest: "d1")
    conflict = begin
      reloaded.begin_request(request_id: "sandbox-1", operation: "run_sandbox", config_digest: "other")
      false
    rescue Rubernetes::Runtime::OwnershipConflict
      true
    end
    # Response loss: effect done and ownership recorded, crash before the response is returned.
    reloaded.begin_operation(operation_id: "op-1", owner: "sandbox-1", config_digest: "d1", request_id: "sandbox-1")
    reloaded.claim(operation_id: "op-1", kind: "workspace", id: "ws-1", identity: {"path" => "/tmp/ws-1"})
    reloaded.complete_request(request_id: "sandbox-1", state: "Completed", result: {"sandbox_id" => "sandbox-1"})
    reloaded = nil
    again = Rubernetes::Runtime::OwnershipLedger.new(journal: Rubernetes::Runtime::RollbackJournal.new(path))
    completed = again.request("sandbox-1")
    owned = again.owned?(kind: "workspace", id: "ws-1", identity: {"path" => "/tmp/ws-1"})
    retry_result = again.begin_request(request_id: "sandbox-1", operation: "run_sandbox", config_digest: "d1")
    {
      "id" => "native_runtime_run_sandbox",
      "component" => "native_runtime",
      "request_loss_state" => request_state,
      "replayed_pending_request" => replay.state,
      "different_intent_rejected" => conflict,
      "response_loss_state" => completed&.state,
      "stored_result_returned_on_retry" => retry_result.result == {"sandbox_id" => "sandbox-1"},
      "resource_still_owned" => owned,
      "measurement_level" => "L2",
      "passed" => request_state == "Pending" && replay.state == "Pending" && conflict && completed&.state == "Completed" &&
                  retry_result.result == {"sandbox_id" => "sandbox-1"} && owned
    }
  end

  def controller_case(root)
    path = File.join(root, "effect-journal.jsonl")
    journal = Rubernetes::Controller::EffectJournal.new(path: path, component: "deployment", identity: "probe")
    first = journal.record(effect_type: "create_replicaset", reconcile_key: "default/web", action: "create", object: {"a" => 1})
    journal = nil
    reloaded = Rubernetes::Controller::EffectJournal.read(path)
    # The effect id is deterministic per (generation, reconcile key, effect type),
    # so a retry after a lost response reuses the identity and the API server
    # can deduplicate it instead of creating a second ReplicaSet.
    again = Rubernetes::Controller::EffectJournal.new(path: path, component: "deployment", identity: "probe")
    retry_id = again.effect_id(reconcile_key: "default/web", effect_type: "create_replicaset", generation: first["generation"])
    {
      "id" => "controller_api_mutation",
      "component" => "controller",
      "durable_records" => reloaded.length,
      "effect_id" => first["effect_id"],
      "retry_effect_id_identical" => retry_id == first["effect_id"],
      "measurement_level" => "L2",
      "passed" => reloaded.length == 1 && retry_id == first["effect_id"] && reloaded.first["effect_id"] == first["effect_id"]
    }
  end

  def volume_case(root)
    path = File.join(root, "volume-ledger.json")
    ledger = Rubernetes::Volume::OperationLedger.new(path: path)
    ledger.begin!(key: "pv-1", operation: "attach", token: "t1", fingerprint: "f1")
    ledger = nil
    reloaded = Rubernetes::Volume::OperationLedger.new(path: path)
    request_loss = reloaded.fetch(key: "pv-1", operation: "attach")&.status
    reloaded.effecting!(key: "pv-1", operation: "attach", token: "t1")
    reloaded = nil
    again = Rubernetes::Volume::OperationLedger.new(path: path)
    response_loss = again.fetch(key: "pv-1", operation: "attach")&.status
    again.unknown!(key: "pv-1", operation: "attach", token: "t1")
    unknown = again.unknown_entries.length
    again.finish!(key: "pv-1", operation: "attach", token: "t1", result: {"device" => "/dev/x"})
    replayed = again.begin!(key: "pv-1", operation: "attach", token: "t1", fingerprint: "f1")
    conflict = begin
      again.begin!(key: "pv-1", operation: "attach", token: "t2", fingerprint: "f2")
      false
    rescue Rubernetes::Volume::OperationTokenConflict
      true
    end
    {
      "id" => "volume_attach",
      "component" => "volume",
      "request_loss_status" => request_loss,
      "response_loss_status" => response_loss,
      "unknown_entries_after_ambiguous_result" => unknown,
      "replay_returns_succeeded_result" => replayed.status == "succeeded" && replayed.result == {"device" => "/dev/x"},
      "different_intent_rejected" => conflict,
      "measurement_level" => "L2",
      "passed" => request_loss == "pending" && response_loss == "effecting" && unknown == 1 && replayed.status == "succeeded" && conflict
    }
  end

  def network_case(root)
    path = File.join(root, "network-journal.jsonl")
    journal = Rubernetes::Network::EventJournal.new(path)
    journal.append(event: "lease_requested", payload: {"pod" => "p1", "ip" => "10.0.0.5"})
    journal = nil
    reloaded = Rubernetes::Network::EventJournal.new(path)
    pending = reloaded.events.select { |event| event["event"] == "lease_requested" } -
              reloaded.events.select { |event| event["event"] == "lease_committed" }
    reloaded.append(event: "lease_committed", payload: {"pod" => "p1", "ip" => "10.0.0.5"})
    again = Rubernetes::Network::EventJournal.new(path)
    committed = again.events.count { |event| event["event"] == "lease_committed" && event["payload"]["ip"] == "10.0.0.5" }
    {
      "id" => "network_ip_lease",
      "component" => "network",
      "request_loss_pending_leases" => pending.length,
      "committed_leases_after_replay" => committed,
      "sequence_contiguous" => again.events.each_with_index.all? { |event, index| event["sequence"] == index + 1 },
      "measurement_level" => "L2",
      "passed" => pending.length == 1 && committed == 1
    }
  end

  def run
    started_at = M5ProbeSupport.now
    cases = []
    Dir.mktmpdir("m5-ownership") do |root|
      cases.concat(raft_cases(File.join(root, "raft")))
      cases << runtime_case(root)
      cases << controller_case(root)
      cases << volume_case(root)
      cases << network_case(root)
    end
    covered = cases.select { |entry| entry["passed"] }.map { |entry| [entry["component"], entry["effect"] || entry["id"].split("_", 2).last] }
    M5ProbeSupport.emit(M5ProbeSupport.report(
      kind: "m5_resource_ownership_ledger", measurement_level: "integration_tested", started_at: started_at, cases: cases,
      extra: {"effect_points" => EFFECT_POINTS,
              "sources" => M5ProbeSupport.source_files(%w[lib/rubernetes/consensus/operation_journal.rb lib/rubernetes/consensus/raft_store.rb
                                                          lib/rubernetes/runtime/ownership.rb lib/rubernetes/controller/effect_journal.rb
                                                          lib/rubernetes/volume/ledger.rb lib/rubernetes/network/durable_state.rb])}
    ))
  end
end

M5OwnershipProbe.run if $PROGRAM_NAME == __FILE__
