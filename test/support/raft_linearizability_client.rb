# frozen_string_literal: true

# Drives a RaftSimulation cluster with concurrent virtual clients and records
# an invoke/ok/fail/info history for the linearizability checker.  Each
# client issues one operation at a time to some live node; a proposal that
# was accepted but whose result never came back before the client gave up
# is recorded as `info` (unknown outcome).

require_relative "raft_simulation"
require "rubernetes/observability/history"

module RaftLinearizabilityClient
  Pending = Struct.new(:client, :input, :request_id, :node_id, :issued_at, :deadline, :index, :term)

  class Driver
    attr_reader :history

    def initialize(cluster, clients:, random:, operation_timeout: 1.0)
      @cluster = cluster
      @clients = clients
      @random = random
      @timeout = operation_timeout
      @history = Rubernetes::Observability::History.new(clock: -> { cluster.now })
      @pending = {}
      @counter = 0
      @results = Hash.new { |hash, key| hash[key] = {} }
      cluster.processes.each_value { |process| attach(process) }
    end

    def attach(process)
      driver = self
      process.node.on_applied do |applied|
        driver.record_apply(process.id, applied)
      end
    end

    def record_apply(node_id, applied)
      command = applied.command
      return unless command.is_a?(Hash) && command["request_uid"]

      @results[node_id][command["request_uid"]] = applied
    end

    # Issue operations for idle clients and settle finished ones.
    def step
      settle
      @clients.each do |client|
        next if @pending.key?(client)

        issue(client)
      end
    end

    def idle?
      @pending.empty?
    end

    def finish(extra_time: 3.0)
      @cluster.run(extra_time)
      settle
      @pending.each_value do |pending|
        @history.info(pending.client, pending.input["op"], pending.input, "unresolved at end of run")
      end
      @pending.clear
    end

    private

    def issue(client)
      @counter += 1
      key = "kv/#{%w[a b c].sample(random: @random)}"
      op = %w[create update delete read].sample(random: @random)
      version = @random.rand < 0.5 ? known_version(key) : nil
      input = {"op" => op, "key" => key}
      input["value"] = @counter if %w[create update].include?(op)
      input["expected_version"] = version if %w[update delete].include?(op) && version
      request_id = "lin-#{@counter}"
      live = @cluster.processes.values.select(&:alive)
      return if live.empty?

      # Clients prefer the current leader, as a real client following a
      # NotLeader redirect would; with a small probability they still try a
      # random node so the redirect path is exercised.
      leaders = live.select { |process| process.node.leader? }
      target = leaders.empty? || @random.rand < 0.1 ? live.sample(random: @random) : leaders.sample(random: @random)
      @history.invoke(client, op, input)
      pending = Pending.new(client, input, request_id, target.id, @cluster.now, @cluster.now + @timeout)
      if op == "read"
        # Reads go through the leader's read index in the simulation: only a
        # leader that has committed in its term answers; others fail.
        node = target.node
        if node.leader?
          begin
            node.read_index do |_index, error|
              if error
                @history.fail(client, op, input, {"status" => "not_leader"})
              else
                object = begin
                  target.state_machine.store.get(key)
                rescue Rubernetes::Storage::NotFound
                  nil
                end
                output = if object
                           {"status" => "ok", "value" => object["spec"]["value"],
                            "version" => Integer(object["metadata"]["resourceVersion"])}
                         else
                           {"status" => "not_found"}
                         end
                @history.ok(client, op, input, output)
              end
              @pending.delete(client)
            end
            @pending[client] = pending
          rescue Rubernetes::Consensus::NotLeader, Rubernetes::Consensus::NotReady
            @history.fail(client, op, input, {"status" => "not_leader"})
          end
        else
          @history.fail(client, op, input, {"status" => "not_leader"})
        end
        return
      end
      command = command_for(input, request_id)
      begin
        target.node.propose(command, request_id: request_id, now: @cluster.now)
        @pending[client] = pending
      rescue Rubernetes::Consensus::NotLeader
        @history.fail(client, op, input, {"status" => "not_leader"})
      end
    end

    def command_for(input, request_id)
      key = input["key"]
      case input["op"]
      when "create"
        {"type" => "create", "key" => key, "object" => {"metadata" => {"name" => key}, "spec" => {"value" => input["value"]}},
         "request_uid" => request_id, "leader_time" => @cluster.now}
      when "update"
        {"type" => "update", "key" => key, "object" => {"metadata" => {"name" => key}, "spec" => {"value" => input["value"]}},
         "expected_resource_version" => input["expected_version"]&.to_s, "request_uid" => request_id, "leader_time" => @cluster.now}
      when "delete"
        {"type" => "delete", "key" => key, "expected_resource_version" => input["expected_version"]&.to_s,
         "request_uid" => request_id, "leader_time" => @cluster.now}
      end
    end

    def known_version(key)
      @cluster.processes.values.select(&:alive).each do |process|
        object = process.state_machine.store.get(key)
        return Integer(object["metadata"]["resourceVersion"])
      rescue Rubernetes::Storage::NotFound
        next
      end
      nil
    end

    def settle
      @pending.each do |client, pending|
        next if pending.input["op"] == "read"

        applied = @results.values.filter_map { |results| results[pending.request_id] }.first
        if applied
          # Every applied command, including a model-level rejection
          # (already_exists / not_found / conflict), is a response the
          # sequential model must explain; only a NotLeader refusal before
          # the proposal was appended is a definite no-op (`fail`).
          @history.ok(client, pending.input["op"], pending.input, translate(applied.result))
          @pending.delete(client)
        elsif @cluster.now >= pending.deadline
          @history.info(client, pending.input["op"], pending.input, "timeout")
          @pending.delete(client)
        end
      end
    end

    def translate(result)
      return {"status" => "ok", "version" => Integer(result["object"]["metadata"]["resourceVersion"])} if result["ok"]

      error = result["error"]
      case error["class"]
      when "Rubernetes::Storage::AlreadyExists" then {"status" => "already_exists"}
      when "Rubernetes::Storage::NotFound" then {"status" => "not_found"}
      when "Rubernetes::Storage::Conflict" then {"status" => "conflict", "current_version" => error["resource_version"] && Integer(error["resource_version"])}
      else {"status" => "error", "class" => error["class"]}
      end
    end
  end
end
