# frozen_string_literal: true

module Rubernetes
  module Runtime
    # kubelet's CFS period and quota, expressed in kernel microseconds.
    module CPUQuota
      CUSTOM_PERIOD_GATE = "CustomCPUCFSQuotaPeriod"
      EXCLUSIVE_CPU_GATE = "DisableCPUQuotaWithExclusiveCPUs"
      DEFAULT_SECONDS = 0.1
      DEFAULT_PERIOD = 100_000
      MIN_QUOTA = 1000

      module_function

      def period_microseconds(seconds)
        (Rational(seconds.to_s) * 1_000_000).to_i
      end

      def from_milli_cpu(milli_cpu, period)
        milli_cpu = Integer(milli_cpu)
        return 0 if milli_cpu.zero?

        [(milli_cpu * Integer(period)) / 1000, MIN_QUOTA].max
      end

      def cgroup_limit(milli_cpu, period:, enabled:)
        quota = enabled ? from_milli_cpu(milli_cpu, period) : 0
        "#{quota.positive? ? quota : "max"} #{period}"
      end
    end
  end
end
