#!/usr/bin/env ruby
# frozen_string_literal: true

# Independent M3 workload oracle entrypoint. The implementation is kept in the
# milestone tooling so the probe and this entrypoint share only the transport
# contract; no expected workload state is stored in the repository.

require "json"

require_relative "../../../../tools/milestones/m3_kubernetes_workload_oracle"

begin
  puts JSON.generate(M3KubernetesWorkloadOracle.run)
rescue StandardError => error
  warn error.message
  exit 1
end
