# frozen_string_literal: true

module Rubernetes
  module Scheduler
    module Scores
      # A plugin's PreScore answered Skip: it takes no part in this cycle.
      SKIP = Object.new.tap do |value|
        def value.inspect = "Scores::SKIP"
        value.freeze
      end
      MAX_NODE_SCORE = 100

      module Normalize
        module_function

        # framework/plugins/helper.DefaultNormalizeScore.
        def default(scores, reverse: false)
          max_count = scores.values.max.to_i
          max_count = 0 if max_count.negative?
          if max_count.zero?
            return reverse ? scores.transform_values { MAX_NODE_SCORE } : scores
          end

          scores.transform_values do |score|
            value = MAX_NODE_SCORE * score / max_count
            reverse ? MAX_NODE_SCORE - value : value
          end
        end
      end

      # A per-node #call on top of #score_nodes, for callers that score one
      # node at a time (every node of the context counts as feasible).
      module NodeSetScorer
        def call(pod, node, context = nil)
          nodes = Filters::Helpers.context_nodes(context)
          nodes = [node] unless nodes.any? { |candidate| candidate.name == node.name }
          result = score_nodes(pod, nodes, context)
          result.equal?(SKIP) ? 0 : result.fetch(node.name, 0)
        end

        alias score call
      end

      class LeastAllocated
        DEFAULT_RESOURCES = %w[cpu memory].freeze

        def call(pod, node, _context = nil)
          allocatable = node.allocatable
          resources = DEFAULT_RESOURCES.select { |resource| allocatable.fetch(resource, Rational(0)).positive? }
          return 0 if resources.empty?

          node_requested = node.non_zero_requested
          # v1.36.2 NewFit never sets enablePodLevelResources on its scorer
          # (fit.go getScorer), so the incoming Pod is scored without its
          # pod-level requests while the node's Pods keep theirs.  Matching
          # the upstream scheduler means matching that.
          pod_requests = Support.non_zero_requests_for(pod, skip_pod_level: true)
          scores = resources.map do |resource|
            capacity = allocatable.fetch(resource)
            # useRequested=false: NonZeroRequested on both sides.
            used = node_requested.fetch(resource, Rational(0)) + pod_requests.fetch(resource, Rational(0))
            next 0 if used > capacity

            ((capacity - used) * 100 / capacity).floor
          end
          score = scores.sum.div(scores.length)
          [[score, 0].max, 100].min
        end

        alias score call
      end

      # tainttoleration: the number of PreferNoSchedule taints the Pod does
      # not tolerate, reversed by DefaultNormalizeScore over the feasible nodes.
      class TaintToleration
        include NodeSetScorer

        def score_nodes(pod, nodes, _context = nil)
          tolerations = pod.tolerations.select do |toleration|
            %w[PreferNoSchedule].include?(Support.value(toleration, "effect",
                                                        "").to_s) || Support.value(toleration, "effect", "").to_s.empty?
          end
          raw = nodes.to_h do |node|
            [node.name, node.taints.count do |taint|
              Support.value(taint, "effect", "").to_s == "PreferNoSchedule" &&
                tolerations.none? { |toleration| Filters::Helpers.tolerates?(toleration, taint) }
            end]
          end
          Normalize.default(raw, reverse: true)
        end
      end

      # nodeaffinity: the weights of the preferred terms a node matches,
      # DefaultNormalizeScore over the feasible nodes; Skip without any.
      class NodeAffinity
        include NodeSetScorer

        def score_nodes(pod, nodes, _context = nil)
          terms = Array(Support.value(pod.node_affinity, "preferredDuringSchedulingIgnoredDuringExecution", []))
          return SKIP if terms.empty?

          Normalize.default(nodes.to_h { |node| [node.name, preferred_score(pod, node)] })
        end

        private

        def preferred_score(pod, node)
          affinity = pod.node_affinity
          terms = Array(Support.value(affinity, "preferredDuringSchedulingIgnoredDuringExecution", []))
          terms.sum do |term|
            term = Support.object_hash(term)
            selector = {"matchExpressions" => Support.value(term, "preference", {}).then do |value|
              Support.value(value, "matchExpressions", [])
            end,
                        "matchFields" => Support.value(term, "preference", {}).then { |value| Support.value(value, "matchFields", []) }}
            matches = Array(selector.fetch("matchExpressions")).all? do |expression|
              requirement_matches?(expression, node.labels)
            end && Array(selector.fetch("matchFields")).all? do |expression|
              requirement_matches?(expression, {"metadata.name" => node.name})
            end
            matches ? Integer(Support.value(term, "weight", 0) || 0) : 0
          rescue ArgumentError, TypeError
            0
          end
        end

        def requirement_matches?(expression, labels)
          expression = Support.object_hash(expression)
          key = Support.value(expression, "key", "").to_s
          operator = Support.value(expression, "operator", "").to_s
          values = Array(Support.value(expression, "values", [])).map(&:to_s)
          present = labels.key?(key)
          actual = labels[key].to_s
          case operator
          when "In" then present && values.include?(actual)
          when "NotIn" then !present || !values.include?(actual)
          when "Exists" then present
          when "DoesNotExist" then !present
          when "Gt" then present && Filters::Helpers.numeric_compare(actual, values.first, :>)
          when "Lt" then present && Filters::Helpers.numeric_compare(actual, values.first, :<)
          else false
          end
        end
      end

      # interpodaffinity/scoring.go.  Every existing Pod contributes, per
      # topology domain of its node: the incoming Pod's preferred (anti-)
      # affinity terms that match it, its own required affinity terms that
      # match the incoming Pod (hardPodAffinityWeight 1) and its own preferred
      # (anti-)affinity terms that match the incoming Pod.  A node scores the
      # sum for its domains; min-max normalization over the feasible nodes.
      # Skip when no node contributes anything.
      class InterPodAffinity
        include NodeSetScorer

        HARD_POD_AFFINITY_WEIGHT = 1

        def score_nodes(pod, nodes, context = nil)
          own_affinity = Array(Support.value(pod.pod_affinity, "preferredDuringSchedulingIgnoredDuringExecution", []))
          own_anti = Array(Support.value(pod.pod_anti_affinity, "preferredDuringSchedulingIgnoredDuringExecution", []))
          has_constraints = !own_affinity.empty? || !own_anti.empty?
          topology_score = Hash.new { |hash, key| hash[key] = Hash.new(0) }
          contributed = false
          Filters::Helpers.context_pods(context).each do |existing|
            next unless has_constraints || with_affinity?(existing)

            existing_node = Filters::Helpers.node_for_pod(existing, context)
            next if existing_node.nil? || existing_node.labels.empty?

            add = lambda do |term, weight, target, owner|
              base = Support.value(term, "podAffinityTerm", term)
              key = Support.value(base, "topologyKey", "").to_s
              value = existing_node.labels[key]
              next if key.empty? || value.nil? || !Filters::Helpers.matching_pod?(target, base, owner, context)

              topology_score[key][value] += weight
              contributed = true
            end
            own_affinity.each { |term| add.call(term, weight(term), existing, pod) }
            own_anti.each { |term| add.call(term, -weight(term), existing, pod) }
            Array(Support.value(existing.pod_affinity, "requiredDuringSchedulingIgnoredDuringExecution", [])).each do |term|
              add.call(term, HARD_POD_AFFINITY_WEIGHT, pod, existing)
            end
            Array(Support.value(existing.pod_affinity, "preferredDuringSchedulingIgnoredDuringExecution", [])).each do |term|
              add.call(term, weight(term), pod, existing)
            end
            Array(Support.value(existing.pod_anti_affinity, "preferredDuringSchedulingIgnoredDuringExecution", [])).each do |term|
              add.call(term, -weight(term), pod, existing)
            end
          end
          return SKIP unless contributed

          raw = nodes.to_h do |node|
            [node.name, topology_score.sum { |key, values| node.labels.key?(key) ? values[node.labels[key]] : 0 }]
          end
          minimum, maximum = raw.values.minmax
          difference = maximum.to_i - minimum.to_i
          raw.transform_values { |score| difference.positive? ? (MAX_NODE_SCORE * (score - minimum).to_f / difference).to_i : 0 }
        end

        private

        def weight(term)
          Integer(Support.value(term, "weight", 1) || 1)
        rescue ArgumentError, TypeError
          1
        end

        # NodeInfo.PodsWithAffinity: any pod (anti-)affinity term at all.
        def with_affinity?(pod)
          [pod.pod_affinity, pod.pod_anti_affinity].any? do |affinity|
            %w[requiredDuringSchedulingIgnoredDuringExecution preferredDuringSchedulingIgnoredDuringExecution].any? do |field|
              !Array(Support.value(affinity, field, [])).empty?
            end
          end
        end
      end

      class ImageLocality
        MIN_THRESHOLD = 23 * 1024 * 1024
        MAX_CONTAINER_THRESHOLD = 1000 * 1024 * 1024

        def call(pod, node, context = nil)
          images = image_names(pod)
          return 0 if images.empty?

          nodes = Array(Filters::Helpers.context_nodes(context))
          raw = raw_score(images, node, [nodes.length, 1].max).to_i
          max_score = MAX_CONTAINER_THRESHOLD * images.length
          min_score = MIN_THRESHOLD
          return 0 if max_score <= min_score

          bounded = [[raw, min_score].max, max_score].min
          ((bounded - min_score) * 100 / (max_score - min_score)).clamp(0, 100)
        rescue StandardError
          # A score plugin must never raise: a raise here previously killed the
          # whole scheduler.  An unscorable node simply contributes 0.
          0
        end

        alias score call

        private

        def image_names(pod)
          containers = Array(pod.containers).dup.concat(Array(pod.init_containers))
          names = containers.filter_map { |container| Support.value(container, "image", nil) }
          names.concat(pod.volumes.filter_map do |volume|
            image = Support.value(volume, "image", nil)
            Support.value(image, "reference", nil) if image
          end)
          names.map { |name| normalize_name(name) }.uniq
        end

        def raw_score(images, node, total_nodes)
          states = image_states(node)
          images.sum do |image|
            state = states[image] || states[normalize_name(image)]
            next 0 unless state

            size = Integer(Support.value(state, "sizeBytes", Support.value(state, "size", 0)) || 0)
            spread = Integer(Support.value(state, "numNodes", Support.value(state, "nodes", 1)) || 1)
            size * spread / [total_nodes, 1].max
          rescue ArgumentError, TypeError
            0
          end
        end

        def image_states(node)
          raw = node.image_states
          return raw if raw.is_a?(Hash)

          Array(raw).each_with_object({}) do |state, result|
            names = Array(Support.value(state, "names", Support.value(state, "name", nil))).map { |name| normalize_name(name) }
            names.each { |name| result[name] = state }
          end
        end

        def normalize_name(name)
          text = name.to_s
          return text if text.include?("@")

          text.include?(":") && text.rindex(":") > text.rindex("/") ? text : "#{text}:latest"
        end
      end

      # Kubernetes v1.36.2 scores the improvement in balance caused by the
      # pending Pod. The default resource set is CPU and memory with weight 1.
      class NodeResourcesBalancedAllocation
        DEFAULT_RESOURCES = %w[cpu memory].freeze

        # PreScore: a BestEffort Pod (useRequested, so no defaults) skips.
        def score_nodes(pod, nodes, context = nil)
          return SKIP if best_effort?(pod.requests)

          nodes.to_h { |node| [node.name, call(pod, node, context)] }
        end

        def best_effort?(requests)
          DEFAULT_RESOURCES.all? { |resource| requests.fetch(resource, Rational(0)).zero? }
        end

        def call(pod, node, _context = nil)
          requests = pod.requests
          resources = DEFAULT_RESOURCES.select { |resource| node.allocatable.fetch(resource, Rational(0)).positive? }
          return 0 if resources.empty? || best_effort?(requests)

          allocated = resources.map { |resource| node.requested.fetch(resource, Rational(0)) }
          requested = resources.each_with_index.map do |resource, index|
            allocated.fetch(index) + requests.fetch(resource, Rational(0))
          end
          allocatable = resources.map { |resource| node.allocatable.fetch(resource) }
          with_pod = balance_score(requested, allocatable)
          without_pod = balance_score(allocated, allocatable)
          score = 50 + (50 + with_pod - without_pod).div(2)
          [[score, 0].max, 100].min
        end

        alias score call

        private

        def balance_score(requested, allocatable)
          fractions = requested.each_index.filter_map do |index|
            capacity = allocatable.fetch(index)
            next if capacity.zero?

            [[requested.fetch(index).to_f / capacity, 0.0].max, 1.0].min
          end
          return 100 if fractions.length < 2

          mean = fractions.sum / fractions.length
          variance = fractions.sum { |fraction| (fraction - mean)**2 } / fractions.length
          ((1.0 - Math.sqrt(variance)) * 100).to_i.clamp(0, 100)
        end
      end

      # podtopologyspread/scoring.go.  Soft (ScheduleAnyway) constraints, or
      # the system default ones when the Pod declares none; pods matching each
      # constraint's selector are counted per topology value over every node
      # (honouring the Pod's required node affinity, nodeAffinityPolicy Honor),
      # a node scores sum(count * log(domains + 2) + maxSkew - 1), and the
      # scores are reversed over the feasible nodes.  Skip without constraints.
      class TopologySpread
        include NodeSetScorer

        HOSTNAME = "kubernetes.io/hostname"
        # config.DefaultPodTopologySpreadConstraints (systemDefaulted).
        SYSTEM_DEFAULT_CONSTRAINTS = [
          {"topologyKey" => HOSTNAME, "whenUnsatisfiable" => "ScheduleAnyway", "maxSkew" => 3},
          {"topologyKey" => "topology.kubernetes.io/zone", "whenUnsatisfiable" => "ScheduleAnyway", "maxSkew" => 5}
        ].freeze

        def score_nodes(pod, nodes, context = nil)
          declared = pod.topology_spread_constraints
          constraints = if declared.empty?
                          default_constraints(pod, context)
                        else
                          declared.filter_map do |constraint|
                            constraint = Support.object_hash(constraint)
                            next unless Support.value(constraint, "whenUnsatisfiable", "").to_s == "ScheduleAnyway"

                            {"topologyKey" => Support.value(constraint, "topologyKey", "").to_s,
                             "maxSkew" => Integer(Support.value(constraint, "maxSkew", 1) || 1),
                             "selector" => merge_match_label_keys(Support.object_hash(Support.value(constraint, "labelSelector", {})),
                                                                  constraint, pod)}
                          end
                        end
          return SKIP if constraints.empty?

          require_all = !declared.empty?
          ignored = require_all ? nodes.reject { |node| all_keys?(node, constraints) }.map(&:name) : []
          counts = constraints.map { {} }
          sizes = constraints.map { 0 }
          nodes.each do |node|
            next if ignored.include?(node.name)

            constraints.each_with_index do |constraint, index|
              next if constraint["topologyKey"] == HOSTNAME

              value = node.labels[constraint["topologyKey"]].to_s
              next if counts[index].key?(value)

              counts[index][value] = 0
              sizes[index] += 1
            end
          end
          weights = constraints.each_with_index.map do |constraint, index|
            size = constraint["topologyKey"] == HOSTNAME ? nodes.length - ignored.length : sizes[index]
            Math.log(size + 2)
          end
          affinity = Filters::NodeAffinity.new
          by_node = pods_by_node(context)
          Filters::Helpers.context_nodes(context).each do |node|
            next unless affinity.call(pod, node) == true
            next if require_all && !all_keys?(node, constraints)

            constraints.each_with_index do |constraint, index|
              value = node.labels[constraint["topologyKey"]].to_s
              next unless counts[index].key?(value)

              counts[index][value] += matching(by_node[node.name], constraint["selector"], pod)
            end
          end
          raw = nodes.to_h do |node|
            next [node.name, nil] if ignored.include?(node.name)

            score = constraints.each_with_index.sum do |constraint, index|
              key = constraint["topologyKey"]
              next 0.0 unless node.labels.key?(key)

              count = if key == HOSTNAME
                        matching(by_node[node.name], constraint["selector"],
                                 pod)
                      else
                        counts[index].fetch(node.labels[key].to_s, 0)
                      end
              (count * weights[index]) + (constraint["maxSkew"] - 1)
            end
            [node.name, score.round]
          end
          valid = raw.values.compact
          minimum = valid.min || 0
          maximum = [valid.max || 0, 0].max
          raw.transform_values do |score|
            next 0 if score.nil?
            next MAX_NODE_SCORE if maximum.zero?

            MAX_NODE_SCORE * (maximum + minimum - score) / maximum
          end
        end

        private

        def all_keys?(node, constraints)
          constraints.all? { |constraint| node.labels.key?(constraint["topologyKey"]) }
        end

        def pods_by_node(context)
          Filters::Helpers.context_pods(context).group_by(&:node_name)
        end

        # countPodsMatchSelector: live pods of the Pod's namespace.
        def matching(pods, selector, pod)
          Array(pods).count do |existing|
            existing.namespace == pod.namespace && Support.value(existing.metadata, "deletionTimestamp", nil).nil? &&
              Filters::Helpers.selector_matches?(existing.labels, selector)
          end
        end

        def default_constraints(pod, context)
          selector = default_selector(pod, context)
          return [] if selector.nil?

          SYSTEM_DEFAULT_CONSTRAINTS.map { |constraint| constraint.merge("selector" => selector) }
        end

        # helper.DefaultSelector: the selectors of the Services selecting the
        # Pod, plus that of its controller when it is a ReplicationController,
        # ReplicaSet or StatefulSet.  Needs the context's workload selectors.
        def default_selector(pod, context)
          data = context.respond_to?(:workload_selectors) ? context.workload_selectors : nil
          return nil unless data.is_a?(Hash)

          match_labels = {}
          expressions = []
          Array(data["services"]).each do |service|
            next unless Support.value(service, "namespace", "").to_s == pod.namespace

            selector = Support.value(service, "selector", nil)
            next unless selector.is_a?(Hash)
            next unless selector.all? { |key, value| pod.labels[key.to_s] == value.to_s }

            match_labels.merge!(selector.to_h { |key, value| [key.to_s, value.to_s] })
          end
          owner = Array(Support.value(pod.metadata, "ownerReferences", [])).find do |reference|
            Support.value(reference, "controller", false) == true
          end
          if owner
            kind = Support.value(owner, "kind", "").to_s
            api_version = Support.value(owner, "apiVersion", "").to_s
            key = "#{kind}/#{pod.namespace}/#{Support.value(owner, "name", "")}"
            controller = Support.object_hash(data["controllers"] || {})[key]
            if controller.is_a?(Hash)
              if kind == "ReplicationController" && api_version == "v1"
                match_labels.merge!(controller.to_h { |label, value| [label.to_s, value.to_s] })
              elsif %w[ReplicaSet StatefulSet].include?(kind) && api_version == "apps/v1"
                Support.object_hash(Support.value(controller, "matchLabels", {})).each do |label, value|
                  expressions << {"key" => label.to_s, "operator" => "In", "values" => [value.to_s]}
                end
                expressions.concat(Array(Support.value(controller, "matchExpressions", [])))
              end
            end
          end
          return nil if match_labels.empty? && expressions.empty?

          {"matchLabels" => match_labels, "matchExpressions" => expressions}
        end

        def merge_match_label_keys(selector, constraint, pod)
          selector = Support.deep_copy(selector)
          labels = pod.labels
          Array(Support.value(constraint, "matchLabelKeys", [])).each do |key|
            key = key.to_s
            next unless labels.key?(key)

            selector["matchLabels"] = Support.object_hash(Support.value(selector, "matchLabels", {}))
            selector["matchLabels"][key] = labels[key]
          end
          selector
        end
      end

      LeastAllocatedScore = LeastAllocated unless const_defined?(:LeastAllocatedScore, false)
      NodeResourcesFit = LeastAllocated unless const_defined?(:NodeResourcesFit, false)
      TaintTolerationScore = TaintToleration unless const_defined?(:TaintTolerationScore, false)
      NodeAffinityScore = NodeAffinity unless const_defined?(:NodeAffinityScore, false)
      InterPodAffinityScore = InterPodAffinity unless const_defined?(:InterPodAffinityScore, false)
      BalancedAllocation = NodeResourcesBalancedAllocation unless const_defined?(:BalancedAllocation, false)
      TopologySpreadScore = TopologySpread unless const_defined?(:TopologySpreadScore, false)
    end
  end
end
