# frozen_string_literal: true

module Rubernetes
  module Runtime
    # cgroup v2 MemoryQoS in kubelet's Linux runtime and pod container manager.
    module MemoryQoS
      DEFAULT_THROTTLING_FACTOR = 0.9
      TIERED_RESERVATION = "TieredReservation"
      RESERVATION_POLICIES = ["None", TIERED_RESERVATION].freeze
      PAGE_SIZE = 4096

      module_function

      def container(request:, limit:, qos:, policy: "None", factor: DEFAULT_THROTTLING_FACTOR, allocatable: nil)
        settings = reservation(request, qos: qos, policy: policy)
        settings = {"memory.min" => "0", "memory.low" => "0"} if settings.empty?
        ceiling = limit.zero? ? allocatable.to_i : limit
        if request != limit && ceiling.positive?
          high = ((request + ((ceiling - request) * factor)) / PAGE_SIZE).floor * PAGE_SIZE
          settings["memory.high"] = high.to_s if high.positive? && high > request
        end
        settings
      end

      def reservation(request, qos:, policy:)
        return {} unless policy == TIERED_RESERVATION && request.positive?

        file = qos.to_s.casecmp?("Guaranteed") ? "memory.min" : "memory.low"
        {file => request.to_s}
      end
    end
  end
end
