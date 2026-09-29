# frozen_string_literal: true

module Rubernetes
  module Scheduler
    module Preemption
      # Raised when the configured exact-search budget is exhausted before
      # every candidate victim set has been evaluated. Returning the best set
      # seen so far would violate the minimum-victim-set contract.
      class BudgetExceeded < PreemptionError
        attr_reader :evaluations, :max_evaluations

        def initialize(evaluations:, max_evaluations:)
          @evaluations = evaluations
          @max_evaluations = max_evaluations
          super("preemption exact-search budget exhausted after #{evaluations} evaluations " +                "(max #{max_evaluations})")
        end
      end

      class Result
        attr_reader :node, :victims, :reason

        def initialize(node:, victims:, reason:)
          @node = node
          @victims = Array(victims).freeze
          @reason = reason.to_s.freeze
          freeze
        end

        def empty?
          victims.empty?
        end

        def to_h
          {"node" => node.name, "victims" => victims.map { |pod| pod.to_h }, "reason" => reason}
        end
      end

      # Finds the smallest deterministic victim set that makes every scheduler
      # filter pass.  Small clusters use materialized exhaustive combinations;
      # large clusters use lazy combinations with an evaluation budget so the
      # minimum-set contract is preserved without an unbounded pause.
      class Evaluator
        DEFAULT_EXACT_LIMIT = 12
        DEFAULT_MAX_EVALUATIONS = 100_000

        def initialize(exact_limit: DEFAULT_EXACT_LIMIT, max_evaluations: DEFAULT_MAX_EVALUATIONS)
          @exact_limit = if exact_limit.is_a?(Integer)
                            exact_limit
                          elsif exact_limit.is_a?(String) && exact_limit.match?(/\A\+?\d+\z/)
                            Integer(exact_limit, 10)
                          else
                            raise ValidationError, "preemption exact_limit must be a positive integer"
                          end
          raise ValidationError, "preemption exact_limit must be positive" unless @exact_limit.positive?
          @max_evaluations = if max_evaluations.is_a?(Integer)
                               max_evaluations
                             elsif max_evaluations.is_a?(String) && max_evaluations.match?(/\A\+?\d+\z/)
                               Integer(max_evaluations, 10)
                             else
                               raise ValidationError, "preemption max_evaluations must be a positive integer"
                             end
          raise ValidationError, "preemption max_evaluations must be positive" unless @max_evaluations.positive?
        end

        def find(pod, nodes:, pods:, filter:)
          pending = pod.is_a?(Pod) ? pod : Pod.new(pod)
          return nil if pending.preemption_policy == "Never"

          all_pods = normalize_pods(pods)
          eligible = all_pods.select { |candidate| candidate.priority < pending.priority }
          return nil if eligible.empty?

          node_list = Array(nodes).map { |node| node.is_a?(Node) ? node : Node.new(node) }.sort_by(&:name)
          candidates = []
          evaluations = 0
          search_exhausted = false
          node_list.each do |node|
            break if search_exhausted

            assigned = assigned_to_node(node, all_pods)
            victims = eligible.select { |candidate| assigned.any? { |item| same_pod?(item, candidate) } }
            next if victims.empty?

            # default_preemption.go selectVictimsOnNode: remove every
            # lower-priority Pod; if the preemptor still does not fit, this
            # node cannot help.  Otherwise reprieve the removed Pods from the
            # MOST important down, keeping each one whose return still leaves
            # room, and evict only the ones that could not be kept.  Searching
            # for the smallest victim set instead evicts a single important
            # Pod rather than two unimportant ones -- "[sig-scheduling]
            # SchedulerPreemption PreemptionExecutionPath" expects the p1 and
            # p2 ReplicaSets preempted and the p3 one left alone, and got its
            # p3 Pod recreated.
            evaluations += 1
            if evaluations > @max_evaluations
              search_exhausted = true
              break
            end
            without = ->(set) { assigned.reject { |candidate| set.any? { |victim| same_pod?(candidate, victim) } } }
            everyone_else = ->(set) { all_pods.reject { |candidate| set.any? { |victim| same_pod?(candidate, victim) } } }
            next unless filter.call(node.with_pods(without.call(victims)), everyone_else.call(victims))

            evicted = victims.dup
            more_important_first(victims).each do |candidate|
              evaluations += 1
              if evaluations > @max_evaluations
                # A victim set cut short is not the one upstream would pick;
                # never act on it.
                search_exhausted = true
                break
              end
              trial = evicted.reject { |victim| same_pod?(victim, candidate) }
              evicted = trial if filter.call(node.with_pods(without.call(trial)), everyone_else.call(trial))
            end
            break if search_exhausted

            candidates << Result.new(node: node, victims: evicted, reason: "preempted lower-priority pods")
          end
          if search_exhausted
            raise BudgetExceeded.new(evaluations: evaluations, max_evaluations: @max_evaluations)
          end
          candidates.min_by { |result| ordering(result) }
        end

        # Adapter used by the local PostFilter registry.  The full framework
        # supplies the same filter closure to #find so preemption never falls
        # back to an unconditional success path.
        def call(pod, _node = nil, context = nil)
          return nil unless context && context.respond_to?(:nodes) && context.respond_to?(:pods)

          find(pod, nodes: context.nodes, pods: context.pods,
               filter: lambda do |candidate_node, remaining_pods|
                 candidate_node_filter = Thread.current[:rubernetes_scheduler_filter]
                 # The framework's filter takes the remaining Pods; handing it
                 # the context made its trial context hold a CycleContext as
                 # its only "Pod".
                 candidate_node_filter ? candidate_node_filter.call(candidate_node, remaining_pods) : true
               end)
        end

        alias find_victims find
        alias evaluate find

        private

        def normalize_pods(pods)
          seen = {}
          Array(pods).map { |pod| pod.is_a?(Pod) ? pod : Pod.new(pod) }.each_with_object([]) do |pod, result|
            key = identity(pod)
            existing = seen[key]
            if existing
              next if existing.to_h == pod.to_h

              raise ValidationError, "preemption received conflicting pods for #{key.inspect}"
            end
            seen[key] = pod
            result << pod
          end
        end

        def assigned_to_node(node, pods)
          from_node = Array(node.pods)
          from_cluster = pods.select { |pod| pod.node_name == node.name }
          (from_node + from_cluster).uniq { |pod| identity(pod) }
        end

        def subsets(victims)
          ordered = victims.sort_by { |pod| [pod.priority, pod.namespace, pod.name, pod.uid] }
          if ordered.length <= @exact_limit
            (1..ordered.length).flat_map { |size| ordered.combination(size).to_a }.each
          else
            # Large victim sets stay lazy to avoid allocating all combinations,
            # while remaining exact so a non-prefix minimum set cannot be lost.
            Enumerator.new do |result|
              (1..ordered.length).each do |size|
                ordered.combination(size) { |subset| result << subset }
              end
            end
          end
        end

        # default_preemption.go pickOneNodeForPreemption: the lowest
        # highest-priority victim first, then the lowest priority sum, then
        # the fewest victims; the name makes the choice deterministic.
        def ordering(result)
          [result.victims.map(&:priority).max || 0,
           result.victims.sum(&:priority),
           result.victims.length,
           result.victims.map { |pod| [pod.namespace, pod.name, pod.uid] }.sort,
           result.node.name]
        end

        # util.MoreImportantPod: higher priority first; ties keep a stable,
        # deterministic order.
        def more_important_first(pods)
          pods.sort_by { |pod| [-pod.priority, pod.namespace, pod.name, pod.uid] }
        end

        def identity(pod)
          uid = pod.uid
          uid.empty? ? [pod.namespace, pod.name] : ["uid", uid, pod.namespace, pod.name]
        end

        def same_pod?(left, right)
          identity(left) == identity(right)
        end
      end

      MinimumVictimSet = Evaluator unless const_defined?(:MinimumVictimSet, false)
    end
  end
end
