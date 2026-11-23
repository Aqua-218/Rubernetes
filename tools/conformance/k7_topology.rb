# frozen_string_literal: true

require "securerandom"
require "socket"
require "tempfile"
require "timeout"

module K7Topology
  def memory_to_raft
    servers = api_servers
    raise K7ClusterDriver::Unsupported, "start a single MemoryStore control node with cluster.rb up --k7-bootstrap" unless servers.one?

    server = servers.first
    config_path = server.fetch("config")
    document = YAML.safe_load_file(config_path)
    datastore = document.dig("processes", "rubernetes-apiserver", "datastore")
    unless datastore.fetch("type") == "memory" && datastore["pki_dir"]
      raise K7ClusterDriver::Unsupported, "start a single MemoryStore control node with cluster.rb up --k7-bootstrap"
    end

    with_checkpoint do |checkpoint|
      clients = processes - servers
      clients_with_pids = clients.reverse.map { |process| [process, capture_process!(process)] }
      restarted_at = nil
      evidence = Tempfile.create(["k7-memory-", ".json"], File.join(cluster_root, "run")) do |export|
        source_stopping = false
        pause_requested = false
        begin
          clients_with_pids.each { |_process, pid| Process.kill("TERM", pid) }
          clients_with_pids.each { |process, pid| wait_for_exit!(process, pid) }
          pause_requested = true
          console(server, "service.export_datastore(#{export.path.inspect}, pause_writes: true); :done")
          # Prepare and validate the seed while the original memory store is
          # still available. Any ongoing watches may stay connected.
          data_dir = cluster_data_directory(datastore)
          voter = datastore.fetch("node_id")
          seeded = seed_datastore(export.path, data_dir, voter)
          source_stopping = true
          stop!(server, signal: "TERM")
          datastore["type"] = "raft"
          Tempfile.create(["k7-raft-config-", ".yml"], File.dirname(config_path)) do |config|
            config.chmod(File.stat(config_path).mode & 0o777)
            config.write(YAML.dump(document))
            config.fsync
            File.rename(config.path, config_path)
          end
          start!(server)
          wait_until("Raft API ready", 180) { healthy? }
          verify_checkpoint!(checkpoint)
          observe_voters!([voter])
          reversibility = verify_memory_snapshot!(server, export.path, data_dir, checkpoint)
          {"from" => "memory", "to" => "raft", "seed_revision" => seeded.fetch("revision"),
           "raft_voters" => [voter], "memory_snapshot_round_trip" => reversibility}
        rescue StandardError
          if source_stopping
            saved = File.join(cluster_root, "run", "memory-recovery-#{SecureRandom.hex(8)}.json")
            File.rename(export.path, saved)
            warn "MemoryStore export retained at #{saved}"
          elsif pause_requested
            begin
              console(server, "service.resume_datastore_writes(#{export.path.inspect}); :done")
            rescue StandardError => recovery_error
              warn "could not resume MemoryStore writes: #{recovery_error.message}"
            end
          end
          raise
        ensure
          restarted_at = Time.now.utc
          clients.each { |process| start!(process) unless pid_of(process) }
        end
      end
      clients.each { |process| wait_for_component!(process, restarted_at) }
      evidence
    end
  end

  def single_to_three_node
    servers = api_servers
    unless servers.one? && YAML.safe_load_file(servers.first.fetch("config")).dig("processes", "rubernetes-apiserver", "datastore", "type") == "raft"
      raise K7ClusterDriver::Unsupported, "scale requires one live Raft control node"
    end

    with_checkpoint do |checkpoint|
      cluster_command("scale", "--root", cluster_root, "--controls", "3")
      voters = %w[control-0 control-1 control-2]
      observe_voters!(voters)
      voters.each { |id| verify_checkpoint!(checkpoint, kubeconfig: File.join(cluster_root, "kubeconfig-#{id}")) }
      {"from_voters" => ["control-0"], "to_voters" => voters, "checked_replicas" => voters}
    end
  end

  def observe_voters!(voters)
    servers = api_servers
    names = servers.map { |server| server.fetch("name") }.sort
    raise "expected live descriptors for #{voters.join(", ")}" unless names == voters.map { |id| "apiserver-#{id}" }.sort

    wait_until("committed Raft voters #{voters.join(", ")}", 90) do
      servers.all? do |server|
        pid_of(server) && console(server, "raft.membership.voters.to_a.sort") == voters.sort.inspect
      rescue Errno::ENOENT, Errno::ECONNREFUSED
        false
      end
    end
  end

  def verify_memory_snapshot!(server, exported, data_dir, checkpoint)
    # A write acknowledged by the Raft-backed API must survive the reverse
    # conversion too. Retain the original checkpoint's revision as a separate key.
    with_checkpoint do |raft_checkpoint|
      console(server, "raft.snapshot!; :done")
      before = JSON.parse(File.binread(exported), max_nesting: 512)
      durable = raft_snapshot(data_dir)
      memory = Rubernetes::Storage::MemoryStore.new.import_state(durable)
      raise "Raft snapshot did not round-trip into MemoryStore" unless memory.export_state == durable
      raise "Raft revision regressed" if durable.fetch("revision") < before.fetch("revision")

      [checkpoint, raft_checkpoint].each { |check| verify_durable_checkpoint!(durable, check) }
    end
    true
  end

  def cluster_data_directory(datastore)
    data_dir = File.expand_path(datastore.fetch("data_dir"))
    raise "Raft data directory is outside the cluster" unless data_dir.start_with?("#{File.join(cluster_root, "data")}/")

    data_dir
  end

  def raft_snapshot(data_dir)
    snapshots = Rubernetes::Consensus::SnapshotStore.new(File.join(data_dir, "snapshots"))
    snapshot, = snapshots.latest
    raise "no verified Raft snapshot in #{data_dir}" unless snapshot

    machine = Rubernetes::Consensus::KVStateMachine.new
    machine.restore(snapshot.state)
    machine.store.export_state
  end

  def verify_durable_checkpoint!(state, check)
    key = "registry/v1/configmaps/default/#{check.fetch("name")}"
    record = state.fetch("versions").fetch(key).last.last
    meta = record.fetch("metadata")
    return if meta.fetch("uid") == check.fetch("uid") && meta.fetch("resourceVersion") == check.fetch("resource_version") &&
              record.fetch("data").fetch("value") == check.fetch("value")

    raise "acknowledged configuration changed in the durable Raft snapshot"
  end

  def seed_datastore(state, data_dir, voter)
    raise "missing Raft identity for #{voter}" unless File.directory?(File.join(cluster_root, "raft-pki", voter))

    JSON.parse(cluster_command("seed", "--state", state, "--data-dir", data_dir, "--voter", voter, "--output", "json"))
  end

  def cluster_command(*args)
    out, err, status = Open3.capture3(RbConfig.ruby, "-I", File.join(K7ClusterDriver::ROOT, "lib"), File.join(K7ClusterDriver::ROOT, "exe/rubectl"), "cluster",
                                      *args, chdir: K7ClusterDriver::ROOT)
    raise "rubectl cluster #{args.first} failed: #{err.lines.last(5).join.strip}" unless status.success?

    out
  end

  def console(process, code)
    document = YAML.safe_load_file(process.fetch("config"))
    path = document.fetch("console").fetch("socket")
    response = Timeout.timeout(15) do
      UNIXSocket.open(path) do |socket|
        socket.puts(JSON.generate("op" => "eval", "code" => code))
        JSON.parse(socket.gets.to_s)
      end
    end
    response.fetch("result") { raise "#{process.fetch("name")} console: #{response.fetch("error")}" }
  end

  def with_checkpoint
    name = "k7-#{SecureRandom.hex(8)}"
    value = SecureRandom.hex(16)
    out, err, status = kubectl("create", "configmap", name, "--namespace", "default", "--from-literal=value=#{value}", "-o", "json")
    raise "could not write K7 checkpoint: #{err.strip}" unless status.success?

    metadata = JSON.parse(out).fetch("metadata")
    yield({"name" => name, "value" => value, "uid" => metadata.fetch("uid"), "resource_version" => metadata.fetch("resourceVersion")})
  ensure
    if status&.success?
      _out, cleanup_error, cleanup = kubectl("delete", "configmap", name, "--namespace", "default", "--ignore-not-found", "--wait=false")
      warn "could not remove K7 checkpoint #{name}: #{cleanup_error.strip}" unless cleanup.success?
    end
  end

  def verify_checkpoint!(checkpoint, kubeconfig: ENV.fetch("KUBECONFIG"))
    out, err, status = kubectl("get", "configmap", checkpoint.fetch("name"), "--namespace", "default", "-o", "json", kubeconfig: kubeconfig)
    raise "could not read K7 checkpoint: #{err.strip}" unless status.success?

    current = JSON.parse(out)
    metadata = current.fetch("metadata")
    return if metadata.fetch("uid") == checkpoint.fetch("uid") && metadata.fetch("resourceVersion") == checkpoint.fetch("resource_version") &&
              current.fetch("data").fetch("value") == checkpoint.fetch("value")

    raise "acknowledged K7 checkpoint changed at #{kubeconfig}"
  end
end
