# frozen_string_literal: true

require "digest"

module Conformance
  module K7Contract
    STAGES = [
      {"id" => "memory_to_raft", "description" => "MemoryStore datastore migrated to RaftStore"},
      {"id" => "single_to_three_node", "description" => "single-node cluster grown to 3 control nodes"},
      {"id" => "release_upgrade", "description" => "previous Rubernetes release upgraded to 1.0.0"},
      {"id" => "rollback", "description" => "1.0.0 rolled back to the previous release"},
      {"id" => "apiserver_rolling_restart", "description" => "API server rolling restart"},
      {"id" => "controller_leader_loss", "description" => "controller-manager leader lost"},
      {"id" => "scheduler_leader_loss", "description" => "scheduler leader lost"},
      {"id" => "worker_reboot", "description" => "worker node rebooted"},
      {"id" => "backup_restore", "description" => "backup taken and restored"}
    ].freeze
    STAGE_IDS = STAGES.map { |stage| stage.fetch("id") }.freeze
    SMOKE_SPECS = [
      "[sig-node] ConfigMap should run through a ConfigMap lifecycle [Conformance]",
      "[sig-network] EndpointSlice should create and delete EndpointSlices for a Service with a selector that matches no pods [Conformance]"
    ].freeze

    module_function

    def smoke_focus
      SMOKE_SPECS.map { |name| Regexp.escape(name).gsub("\\ ", " ") }.join("|")
    end

    def state_inventory_sha256
      files = %w[k7_lifecycle.rb k7_state_inventory.rb]
      Digest::SHA256.hexdigest(files.map { |name| Digest::SHA256.file(File.join(__dir__, name)).digest }.join)
    end
  end
end
