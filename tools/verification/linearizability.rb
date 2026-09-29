# frozen_string_literal: true

# Linearizability checker (spec/verification/testing.md 8.3).
#
# Given a history of invoke/ok/fail/info events and a sequential model, the
# checker searches for a total order of the completed operations that is
# consistent with the real-time partial order and with the model.  The
# search is the Wing & Gong / Lowe algorithm with a memoised (linearized set,
# state) cache.  Operations with an unknown outcome (`info`) are treated as
# possibly-applied: they may be linearized at any point after their
# invocation or omitted entirely.
#
# The sequential model is the Ruby KV model; the same model is executable
# in Lean (verification/lean/KVSequential.lean) and the two are compared by
# tools/verification/kv_sequential_oracle.rb so the Ruby model is only used
# after it agrees with the Lean reference on the corpus.

require "json"
require "set"

module Linearizability
  # Sequential key/value model with resourceVersion semantics matching the
  # MemoryStore/RaftStore contract: a global revision increments on every
  # successful mutation; each key holds {value, version}.
  class KVModel
    State = Struct.new(:revision, :objects) do
      def key
        [revision, objects.sort.to_h].hash
      end

      def dup_state
        State.new(revision, objects.dup)
      end
    end

    def initial_state
      State.new(0, {})
    end

    # Returns [ok?, new_state, expected_output] for input {op, key, value, expected_version}.
    def step(state, input)
      op = input.fetch("op")
      key = input["key"]
      case op
      when "create"
        if state.objects.key?(key)
          [state, {"status" => "already_exists"}]
        else
          revision = state.revision + 1
          objects = state.objects.merge(key => {"value" => input["value"], "version" => revision})
          [State.new(revision, objects), {"status" => "ok", "version" => revision}]
        end
      when "update"
        current = state.objects[key]
        return [state, {"status" => "not_found"}] if current.nil?

        expected = input["expected_version"]
        if !expected.nil? && expected != current["version"]
          [state, {"status" => "conflict", "current_version" => current["version"]}]
        else
          revision = state.revision + 1
          objects = state.objects.merge(key => {"value" => input["value"], "version" => revision})
          [State.new(revision, objects), {"status" => "ok", "version" => revision}]
        end
      when "delete"
        current = state.objects[key]
        return [state, {"status" => "not_found"}] if current.nil?

        expected = input["expected_version"]
        if !expected.nil? && expected != current["version"]
          [state, {"status" => "conflict", "current_version" => current["version"]}]
        else
          revision = state.revision + 1
          objects = state.objects.dup
          objects.delete(key)
          [State.new(revision, objects), {"status" => "ok", "version" => revision}]
        end
      when "read"
        current = state.objects[key]
        if current.nil?
          [state, {"status" => "not_found"}]
        else
          [state, {"status" => "ok", "value" => current["value"], "version" => current["version"]}]
        end
      else
        raise ArgumentError, "unknown operation #{op.inspect}"
      end
    end

    # Whether the observed output is consistent with the model output.
    def consistent?(expected, observed)
      return false unless expected["status"] == observed["status"]

      case expected["status"]
      when "ok"
        (expected["version"].nil? || expected["version"] == observed["version"]) &&
          (!expected.key?("value") || expected["value"] == observed["value"])
      when "conflict"
        expected["current_version"].nil? || observed["current_version"].nil? || expected["current_version"] == observed["current_version"]
      else
        true
      end
    end
  end

  Operation = Struct.new(:id, :process, :input, :output, :invoke_time, :return_time, :status)

  class Checker
    attr_reader :operations, :explored

    def initialize(events, model: KVModel.new, max_states: 5_000_000)
      @model = model
      @max_states = max_states
      @operations = build_operations(events)
      @explored = 0
    end

    def check
      complete = @operations.select { |op| op.status == "ok" || op.status == "fail" }
      unknown = @operations.select { |op| op.status == "info" }
      result = search(complete, unknown)
      if result[:linearizable]
        result
      else
        result.merge("witness" => minimal_conflict(complete, unknown))
      end
    end

    private

    def build_operations(events)
      pending = {}
      operations = []
      events.sort_by { |event| [event.fetch("time"), event.fetch("sequence")] }.each do |event|
        type = event.fetch("type")
        process = event.fetch("process")
        case type
        when "invoke"
          pending[process] = Operation.new(operations.length + pending.length, process, event["input"], nil, event["time"], nil, "pending")
        when "ok", "fail", "info"
          op = pending.delete(process)
          raise ArgumentError, "#{type} without invoke for process #{process}" if op.nil?

          op.output = event["output"]
          op.return_time = event["time"]
          op.status = type
          operations << op
        end
      end
      pending.each_value do |op|
        op.status = "info"
        op.return_time = Float::INFINITY
        operations << op
      end
      operations.each_with_index { |op, index| op.id = index }
      operations
    end

    # Depth-first search over linearization orders.  An operation can be
    # linearized next when every operation that returned before it was
    # invoked has already been linearized (real-time order).
    def search(complete, unknown)
      all = complete + unknown
      by_id = all.to_h { |op| [op.id, op] }
      cache = Set.new
      initial = @model.initial_state
      stack = [[Set.new, initial, []]]
      until stack.empty?
        linearized, state, order = stack.pop
        @explored += 1
        return {linearizable: false, "reason" => "state budget exceeded", "explored" => @explored} if @explored > @max_states

        remaining = all.reject { |op| linearized.include?(op.id) }
        if remaining.all? { |op| op.status == "info" }
          # Unknown operations may be dropped; every completed operation is linearized.
          return {linearizable: true, "order" => order.map { |id| by_id[id].input.merge("id" => id) }, "explored" => @explored}
        end
        minimal_return = remaining.select { |op| op.status != "info" }.map(&:return_time).min || Float::INFINITY
        candidates = remaining.select { |op| op.invoke_time <= minimal_return }
        candidates.each do |op|
          next_state, expected = @model.step(state, op.input)
          if op.status == "ok"
            next unless @model.consistent?(expected, op.output)
          elsif op.status == "fail"
            # A failed operation is one the client knows never took effect
            # (for example a NotLeader refusal before the proposal was
            # appended).  It is a no-op in the model and its transport-level
            # error carries no model outcome to compare.
            next_state = state
          end
          new_linearized = linearized.dup << op.id
          cache_key = [new_linearized.to_a.sort, next_state.key]
          next if cache.include?(cache_key)

          cache << cache_key
          stack.push([new_linearized, next_state, order + [op.id]])
        end
      end
      {linearizable: false, "reason" => "no linearization exists", "explored" => @explored}
    end

    # Shrink to a small conflicting operation pair set for the report.
    def minimal_conflict(complete, unknown)
      ordered = complete.sort_by(&:invoke_time)
      (2..[ordered.length, 6].min).each do |size|
        ordered.combination(size).each do |subset|
          @explored = 0
          result = search(subset, [])
          return subset.map { |op| {"process" => op.process, "input" => op.input, "output" => op.output, "status" => op.status} } unless result[:linearizable]
        end
      end
      ordered.first(6).map { |op| {"process" => op.process, "input" => op.input, "output" => op.output, "status" => op.status} }
    end
  end

  module_function

  def check_file(path)
    events = JSON.parse(File.read(path))
    Checker.new(events).check
  end
end

if $PROGRAM_NAME == __FILE__
  result = Linearizability.check_file(ARGV.fetch(0))
  puts JSON.pretty_generate(result)
  exit(result[:linearizable] ? 0 : 1)
end
