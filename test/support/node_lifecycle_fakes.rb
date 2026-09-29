# frozen_string_literal: true

# A recording runtime and status reporter the node lifecycle tests share.
# Kept out of the test files: a test file that requires another one loads it
# twice under the Minitest inventory (which loads every test file itself),
# and the second load redefines its constants.
module NodeLifecycleFakes
  class Runtime
    attr_reader :created, :stopped, :sandboxes

    def initialize
      @counter = 0
      @created = []
      @stopped = []
      @names = {}
      @exited = {}
      @sandboxes = 0
    end

    def run_sandbox(_pod, runtime_class: nil)
      @sandboxes += 1
      "sandbox-#{@sandboxes}"
    end

    def create_container(_sandbox, spec)
      @counter += 1
      id = "c#{@counter}"
      @names[id] = spec["name"]
      @created << spec["name"]
      id
    end

    def start_container(_id) = true

    def container_status(id)
      @exited.key?(id) ? {"state" => "exited", "exit_code" => @exited[id]} : {"state" => "running"}
    end

    def stop_container(id, timeout:)
      @stopped << [@names[id], timeout]
      @exited[id] ||= 137
      true
    end

    def remove_container(_id) = true
    def remove_sandbox(_id) = true
  end

  class Reporter
    attr_reader :statuses

    def initialize = @statuses = []
    def report(_pod, status) = @statuses << status.to_h
  end
end
