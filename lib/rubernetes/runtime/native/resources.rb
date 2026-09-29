# frozen_string_literal: true

# Kubernetes v1.36.2 resource semantics for the Native cgroup v2 hierarchy
# (spec/node/runtime.md §5.8.8).  Every formula cites the kubelet source it
# reproduces; this module is pure so the same numbers can be checked in unit
# tests and recomputed by the evidence gate.

require_relative "../../resource_helpers"

module Rubernetes
  module Runtime
    class Native
      module Resources
        class Error < Native::ConfigurationError; end

        # pkg/kubelet/cm/helpers_linux.go
        MIN_SHARES = 2
        MAX_SHARES = 262_144
        SHARES_PER_CPU = 1024
        MILLI_CPU_TO_CPU = 1000
        QUOTA_PERIOD = 100_000
        MIN_QUOTA_PERIOD = 1000
        # pkg/kubelet/kuberuntime/kuberuntime_container_linux.go (memory.high)
        DEFAULT_PAGE_SIZE = 4096
        DEFAULT_MEMORY_THROTTLING_FACTOR = 0.9
        QOS_CLASSES = %w[guaranteed burstable besteffort].freeze
        QOS_RESOURCES = %w[cpu memory].freeze

        BINARY_SUFFIXES = {"Ki" => 1024, "Mi" => 1024**2, "Gi" => 1024**3, "Ti" => 1024**4, "Pi" => 1024**5, "Ei" => 1024**6}.freeze
        DECIMAL_SUFFIXES = {"n" => Rational(1, 10**9), "u" => Rational(1, 10**6), "m" => Rational(1, 1000), "" => Rational(1),
                            "k" => Rational(1000), "M" => Rational(10**6), "G" => Rational(10**9), "T" => Rational(10**12),
                            "P" => Rational(10**15), "E" => Rational(10**18)}.freeze
        QUANTITY_PATTERN = /\A([+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+))(?:([eE])([+-]?[0-9]+))?(Ki|Mi|Gi|Ti|Pi|Ei|n|u|m|k|M|G|T|P|E)?\z/.freeze

        module_function

        # resource.Quantity parsing (staging/src/k8s.io/apimachinery/pkg/api/resource):
        # decimal or binary SI suffix, or decimal exponent.
        def parse_quantity(value)
          return Rational(value) if value.is_a?(Integer)
          return Rational(value.to_s) if value.is_a?(Float) && value.finite?

          text = String(value).strip
          match = QUANTITY_PATTERN.match(text)
          raise Error, "invalid resource quantity #{value.inspect}" unless match

          number = Rational(match[1])
          number *= Rational(10)**Integer(match[3], 10) if match[3]
          suffix = match[4] || ""
          multiplier = BINARY_SUFFIXES[suffix] || DECIMAL_SUFFIXES.fetch(suffix)
          result = number * multiplier
          raise Error, "resource quantity must not be negative: #{value.inspect}" if result.negative?

          result
        end

        # Quantity#MilliValue rounds up to the next milli unit.
        def milli_cpu(value)
          (parse_quantity(value) * MILLI_CPU_TO_CPU).ceil
        end

        # Quantity#Value rounds up to the next integer unit.
        def bytes(value)
          parse_quantity(value).ceil
        end

        # cm.MilliCPUToQuota: quota in microseconds for the given period.
        def milli_cpu_to_quota(milli, period = QUOTA_PERIOD)
          milli = Integer(milli)
          return 0 if milli.zero?

          quota = (milli * Integer(period)) / MILLI_CPU_TO_CPU
          quota = MIN_QUOTA_PERIOD if quota < MIN_QUOTA_PERIOD
          quota
        end

        # cm.MilliCPUToShares.
        def milli_cpu_to_shares(milli)
          milli = Integer(milli)
          return MIN_SHARES if milli.zero?

          shares = (milli * SHARES_PER_CPU) / MILLI_CPU_TO_CPU
          return MIN_SHARES if shares < MIN_SHARES
          return MAX_SHARES if shares > MAX_SHARES

          shares
        end

        # cm.getCPUWeight (cgroup_manager_linux.go): cgroup v1 shares
        # [2, 262144] mapped onto cgroup v2 weight [1, 10000].
        def shares_to_weight(shares)
          shares = Integer(shares)
          return 1 if shares == 0
          return 10_000 if shares >= MAX_SHARES

          1 + ((shares - 2) * 9999) / 262_142
        end

        def cpu_weight(milli_request)
          shares_to_weight(milli_cpu_to_shares(milli_request))
        end

        # pkg/apis/core/v1/defaults.go: an unspecified request defaults to the
        # limit for the same resource.
        def effective_requirements(container)
          resources = string_keys(fetch(container, "resources") || {})
          limits = string_keys(resources["limits"] || {})
          requests = string_keys(resources["requests"] || {})
          limits.each_key { |name| requests[name] = limits[name] unless requests.key?(name) }
          {"requests" => requests, "limits" => limits}
        end

        def restartable_init?(container)
          fetch(container, "restartPolicy").to_s == "Always"
        end

        # pkg/apis/core/v1/helper/qos.ComputePodQOS, pod-level resources
        # included (ResourceHelpers), in the lower-case form used here.
        def qos_class(pod_spec)
          Rubernetes::ResourceHelpers.qos_class(defaulted_pod(pod_spec)).downcase
        end

        # The API server's container defaulting (a limit without a request is
        # the request too), for specs that did not come through it.
        def defaulted_pod(pod_spec)
          spec = pod_spec_of(pod_spec)
          containers = lambda do |list|
            Array(list).map do |container|
              next container unless container.is_a?(Hash)

              requirements = effective_requirements(container)
              string_keys(container).merge("resources" => string_keys(fetch(container, "resources") || {}).merge(
                "requests" => requirements.fetch("requests"), "limits" => requirements.fetch("limits")
              ))
            end
          end
          defaulted = spec.merge("containers" => containers.call(spec["containers"]))
          defaulted["initContainers"] = containers.call(spec["initContainers"]) if spec.key?("initContainers")
          {"spec" => defaulted}
        end

        def pod_requirements(pod_spec)
          spec = pod_spec_of(pod_spec)
          {"requests" => aggregate(spec, "requests"), "limits" => aggregate(spec, "limits")}
        end

        def aggregate(spec, kind)
          totals = Hash.new(Rational(0))
          declared = {"cpu" => true, "memory" => true}
          Array(spec["containers"]).each do |container|
            values = effective_requirements(container).fetch(kind)
            note_declared(declared, values) if kind == "limits"
            add(totals, values)
          end
          restartable = Hash.new(Rational(0))
          init_max = Hash.new(Rational(0))
          Array(spec["initContainers"]).each do |container|
            values = effective_requirements(container).fetch(kind)
            note_declared(declared, values) if kind == "limits"
            if restartable_init?(container)
              add(totals, values)
              add(restartable, values)
              use = restartable
            else
              use = Hash.new(Rational(0))
              add(use, values)
              add(use, restartable)
            end
            use.each { |name, value| init_max[name] = value if value > init_max[name] }
          end
          init_max.each { |name, value| totals[name] = value if value > totals[name] }
          overhead = string_keys(spec["overhead"] || {})
          overhead.each do |name, quantity|
            value = parse_quantity(quantity)
            if kind == "requests"
              totals[name] += value
            elsif totals.key?(name) && totals[name].positive?
              totals[name] += value
            end
          end
          result = totals.to_h
          result["__declared__"] = declared if kind == "limits"
          result
        end

        # Container cgroup files (kuberuntime calculateLinuxResources +
        # generateLinuxContainerResources).  Hard limits are written only when
        # the corresponding limit is declared (§5.8.8).
        # +pod+: the Pod the container belongs to.  kuberuntime getCPULimit /
        # getMemoryLimit: with pod-level resources set, a container that sets
        # no CPU (memory) limit of its own is limited by the Pod's.
        def container_cgroup_limits(container, qos:, memory_qos: false, pids_limit: nil, cpu_period: QUOTA_PERIOD, pod: nil)
          requirements = effective_requirements(container)
          requests = requirements.fetch("requests")
          limits = requirements.fetch("limits")
          cpu_request = requests.key?("cpu") ? milli_cpu(requests["cpu"]) : nil
          cpu_limit = limits.key?("cpu") ? milli_cpu(limits["cpu"]) : nil
          memory_request = requests.key?("memory") ? bytes(requests["memory"]) : 0
          memory_limit = limits.key?("memory") ? bytes(limits["memory"]) : 0
          own_memory_limit = memory_limit
          pod_object = pod && {"spec" => pod_spec_of(pod)}
          if pod_object && Rubernetes::ResourceHelpers.pod_level_resources_set?(pod_object)
            pod_limits = string_keys(pod_object["spec"].dig("resources", "limits") || {})
            cpu_limit = milli_cpu(pod_limits["cpu"]) if (cpu_limit.nil? || cpu_limit.zero?) && pod_limits.key?("cpu")
            memory_limit = bytes(pod_limits["memory"]) if memory_limit.zero? && pod_limits.key?("memory")
          end
          shares_source = cpu_request.nil? && cpu_limit ? cpu_limit : cpu_request.to_i
          result = {"cpu.weight" => cpu_weight(shares_source).to_s}
          result["cpu.max"] = cpu_limit ? "#{milli_cpu_to_quota(cpu_limit, cpu_period)} #{cpu_period}" : "max #{cpu_period}"
          result["memory.max"] = memory_limit.to_s if memory_limit.positive?
          # cgroup v2 default singleProcessOOMKill=false: the whole cgroup is
          # killed on OOM so a partially killed container never lingers.
          result["memory.oom.group"] = "1"
          if memory_qos
            if memory_request.positive?
              result[String(qos) == "guaranteed" ? "memory.min" : "memory.low"] = memory_request.to_s
            else
              result["memory.min"] = "0"
              result["memory.low"] = "0"
            end
            # memory.high reads the container's own limit, not the Pod's.
            if memory_request != own_memory_limit && own_memory_limit.positive?
              high = ((memory_request + (own_memory_limit - memory_request) * DEFAULT_MEMORY_THROTTLING_FACTOR) / DEFAULT_PAGE_SIZE).floor * DEFAULT_PAGE_SIZE
              result["memory.high"] = high.to_s if high.positive? && high > memory_request
            end
          end
          result["pids.max"] = Integer(pids_limit).to_s if pids_limit && Integer(pids_limit).positive?
          result
        end

        # Pod cgroup files (cm.ResourceConfigForPod).
        def pod_cgroup_limits(pod_spec, qos: qos_class(pod_spec), memory_qos: false, pids_limit: nil, cpu_period: QUOTA_PERIOD)
          helpers = Rubernetes::ResourceHelpers
          pod = defaulted_pod(pod_spec)
          requests = helpers.pod_requests(pod).transform_values(&:value)
          declared = {"cpu" => true, "memory" => true}
          limits = helpers.pod_limits(pod, container_fn: lambda { |list, _type|
            declared["cpu"] = false if list["cpu"].nil? || list["cpu"].zero?
            declared["memory"] = false if list["memory"].nil? || list["memory"].zero?
          }).transform_values(&:value)
          if helpers.pod_level_resources_set?(pod)
            pod_limits = helpers.resource_list(pod["spec"].dig("resources", "limits"))
            declared["cpu"] = true if pod_limits["cpu"] && !pod_limits["cpu"].zero?
            declared["memory"] = true if pod_limits["memory"] && !pod_limits["memory"].zero?
          end
          cpu_requests = requests.key?("cpu") ? (requests["cpu"] * MILLI_CPU_TO_CPU).ceil : 0
          cpu_limits = limits.key?("cpu") ? (limits["cpu"] * MILLI_CPU_TO_CPU).ceil : 0
          memory_limits = limits.key?("memory") ? limits["memory"].ceil : 0
          shares = milli_cpu_to_shares(cpu_requests)
          quota = milli_cpu_to_quota(cpu_limits, cpu_period)
          result = {}
          case String(qos)
          when "guaranteed"
            result["cpu.weight"] = shares_to_weight(shares).to_s
            result["cpu.max"] = "#{quota.positive? ? quota : "max"} #{cpu_period}"
            result["memory.max"] = memory_limits.to_s if memory_limits.positive?
          when "burstable"
            result["cpu.weight"] = shares_to_weight(shares).to_s
            result["cpu.max"] = "#{quota.positive? ? quota : "max"} #{cpu_period}" if declared["cpu"]
            result["memory.max"] = memory_limits.to_s if declared["memory"] && memory_limits.positive?
          else
            result["cpu.weight"] = shares_to_weight(MIN_SHARES).to_s
          end
          if memory_qos && requests.key?("memory") && requests["memory"].positive?
            result[String(qos) == "guaranteed" ? "memory.min" : "memory.low"] = requests["memory"].ceil.to_s
          end
          result["pids.max"] = Integer(pids_limit).to_s if pids_limit && Integer(pids_limit).positive?
          result
        end

        def pod_spec_of(value)
          hash = string_keys(value.respond_to?(:to_h) ? value.to_h : {})
          hash.key?("spec") && hash["spec"].is_a?(Hash) ? string_keys(hash["spec"]) : hash
        end

        def string_keys(value)
          return {} unless value.respond_to?(:to_h)

          value.to_h.each_with_object({}) { |(key, child), result| result[String(key)] = child }
        end

        def fetch(container, name)
          hash = container.respond_to?(:to_h) ? container.to_h : {}
          hash.key?(name) ? hash[name] : hash[name.to_sym]
        end

        def add(totals, values)
          values.each do |name, quantity|
            next unless QOS_RESOURCES.include?(String(name))

            value = parse_quantity(quantity)
            totals[String(name)] += value if value.positive?
          end
        end

        def note_declared(declared, values)
          QOS_RESOURCES.each do |name|
            quantity = values[name]
            declared[name] = false if quantity.nil? || !parse_quantity(quantity).positive?
          end
        end
      end
    end
  end
end
