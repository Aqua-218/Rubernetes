# frozen_string_literal: true

require_relative "topology"

module Rubernetes
  module Node
    module CPUManager
      # pkg/kubelet/cm/cpumanager/cpu_assignment.go: which available CPUs a
      # request of N gets.  takeByTopologyNUMAPacked fills whole NUMA nodes
      # and sockets (in the order the topology nests them), then uncore
      # caches, whole cores and single CPUs, always preferring the fullest
      # fit; takeByTopologyNUMADistributed spreads a request evenly over the
      # fewest NUMA nodes that balance what stays free.
      module Assignment
        class Error < StandardError; end

        PACKED = "packed"
        SPREAD = "spread"

        # A Go []int as iterateCombinations builds it: append writes in place
        # while the backing array has room, so a combination kept past the
        # callback sees the elements later appends wrote into the shared
        # array.  Upstream's distributed allocation keeps its best
        # combination that way; the emulation keeps the results identical.
        class GoSlice
          attr_reader :backing, :length

          def initialize(backing, length)
            @backing = backing
            @length = length
          end

          def self.empty = new([], 0)

          def append(value)
            if @length < @backing.length
              @backing[@length] = value
              GoSlice.new(@backing, @length + 1)
            else
              capacity = @backing.empty? ? 1 : @backing.length * 2
              grown = Array.new(capacity)
              grown[0, @length] = @backing[0, @length]
              grown[@length] = value
              GoSlice.new(grown, @length + 1)
            end
          end

          def to_a = @backing[0, @length]
        end

        # cpuAccumulator.
        class Accumulator
          attr_reader :topology, :details, :needed, :result

          def initialize(topology, available, count, strategy)
            @topology = topology
            @details = topology.cpu_details.keep_only(available)
            @needed = count
            @result = CPUSet.empty
            @numa_first = topology.num_sockets >= topology.num_numa_nodes
            @strategy = strategy
          end

          def satisfied? = @needed < 1
          def failed? = @needed > @details.cpus.size
          def needs_at_least?(count) = @needed >= count

          def take(cpus)
            @result = @result.union(cpus)
            @details = @details.keep_only(@details.cpus.difference(@result))
            @needed -= cpus.size
          end

          # accumulator.sort: by free CPU count, then id.
          def sorted(ids, &)
            ids.to_a.sort_by { |id| [yield(id).size, id] }
          end

          def sort_available_numa_nodes
            if @numa_first
              sorted(@details.numa_nodes) { |id| @details.cpus_in_numa_nodes(id) }
            else
              sort_available_sockets.flat_map do |socket|
                sorted(@details.numa_nodes_in_sockets(socket)) { |id| @details.cpus_in_numa_nodes(id) }
              end
            end
          end

          def sort_available_sockets
            if @numa_first
              sort_available_numa_nodes.flat_map do |numa|
                sorted(@details.sockets_in_numa_nodes(numa)) { |id| @details.cpus_in_sockets(id) }
              end
            else
              sorted(@details.sockets) { |id| @details.cpus_in_sockets(id) }
            end
          end

          def sort_available_cores
            if @numa_first
              sort_available_sockets.flat_map do |socket|
                sorted(@details.cores_in_sockets(socket)) { |id| @details.cpus_in_cores(id) }
              end
            else
              sort_available_numa_nodes.flat_map do |numa|
                sorted(@details.cores_in_numa_nodes(numa)) { |id| @details.cpus_in_cores(id) }
              end
            end
          end

          def sort_available_uncore_caches
            sort_available_numa_nodes.flat_map do |numa|
              sorted(@details.uncore_in_numa_nodes(numa)) { |id| @details.cpus_in_uncore_caches(id) }
            end
          end

          def sort_available_cpus
            if @strategy == PACKED
              sort_available_cores.flat_map { |core| @details.cpus_in_cores(core).to_a }
            else
              sort_available_sockets.flat_map { |socket| @details.cpus_in_sockets(socket).to_a }
            end
          end

          def numa_node_free?(id) = @details.cpus_in_numa_nodes(id).size == @topology.cpu_details.cpus_in_numa_nodes(id).size
          def socket_free?(id) = @details.cpus_in_sockets(id).size == @topology.cpus_per_socket
          def uncore_cache_free?(id) = @details.cpus_in_uncore_caches(id).size == @topology.cpu_details.cpus_in_uncore_caches(id).size
          def core_free?(id) = @details.cpus_in_cores(id).size == @topology.cpus_per_core

          def free_numa_nodes = sort_available_numa_nodes.select { |id| numa_node_free?(id) }
          def free_sockets = sort_available_sockets.select { |id| socket_free?(id) }
          def free_uncore_caches = sort_available_uncore_caches.select { |id| uncore_cache_free?(id) }
          def free_cores = sort_available_cores.select { |id| core_free?(id) }

          def take_full_first_level = @numa_first ? take_full_numa_nodes : take_full_sockets
          def take_full_second_level = @numa_first ? take_full_sockets : take_full_numa_nodes

          def take_full_numa_nodes
            free_numa_nodes.each do |numa|
              cpus = @topology.cpu_details.cpus_in_numa_nodes(numa)
              take(cpus) if needs_at_least?(cpus.size)
            end
          end

          def take_full_sockets
            free_sockets.each do |socket|
              cpus = @topology.cpu_details.cpus_in_sockets(socket)
              take(cpus) if needs_at_least?(cpus.size)
            end
          end

          def take_full_uncore
            free_uncore_caches.each do |uncore|
              cpus = @topology.cpu_details.cpus_in_uncore_caches(uncore)
              take(cpus) if needs_at_least?(cpus.size)
            end
          end

          def take_partial_uncore(uncore)
            per_core = @topology.cpus_per_core
            cores_needed = (@needed + per_core - 1) / per_core
            free_cores = @details.cores_needed_in_uncore_cache(cores_needed, uncore)
            free_cpus = @details.cpus_in_cores(*free_cores.to_a)
            if @needed.odd? && per_core > 1
              list = free_cpus.to_a
              list = list[0, free_cpus.size - 1] if list.length > @needed
              free_cpus = CPUSet.new(list)
            end
            take(free_cpus) if @needed == free_cpus.size
          end

          def take_uncore_cache
            per_uncore = @topology.cpus_per_uncore
            sort_available_uncore_caches.each do |uncore|
              take_full_uncore if needs_at_least?(per_uncore)
              return if satisfied? # rubocop:disable Lint/NonLocalExitFromIterator -- the method is done once this holds

              take_partial_uncore(uncore)
              return if satisfied? # rubocop:disable Lint/NonLocalExitFromIterator -- the method is done once this holds
            end
          end

          def take_full_cores
            free_cores.each do |core|
              cpus = @topology.cpu_details.cpus_in_cores(core)
              take(cpus) if needs_at_least?(cpus.size)
            end
          end

          def take_remaining_cpus
            sort_available_cpus.each do |cpu|
              take(CPUSet[cpu])
              return if satisfied?
            end
          end

          # rangeNUMANodesNeededToSatisfy.
          def numa_range(group_size)
            numa_count = @topology.cpu_details.numa_nodes.size
            available_numa = @details.numa_nodes.size
            cpu_count = @topology.cpu_details.cpus.size
            groups = ((cpu_count - 1) / group_size) + 1
            groups_per_numa = ((groups - 1) / numa_count) + 1
            groups_needed = ((@needed - 1) / group_size) + 1
            [((groups_needed - 1) / groups_per_numa) + 1, [groups_needed, available_numa].min]
          end

          # iterateCombinations: every k-combination of +items+ in order; the
          # block returns :break to stop.  Combinations are GoSlices.
          def iterate_combinations(items, k, &)
            return if k < 1

            helper = lambda do |remaining, start, accum|
              return yield(accum) if remaining.zero?

              i = start
              while i <= items.length - remaining
                return :break if helper.call(remaining - 1, i + 1, accum.append(items[i])) == :break

                i += 1
              end
              :continue
            end
            helper.call(k, 0, GoSlice.empty)
          end
        end

        module_function

        def mean(values)
          (values.sum.to_f / values.length * 1000).round / 1000.0
        end

        # standardDeviation, rounded to three places like upstream (math.Round
        # rounds half away from zero, as Float#round does).
        def standard_deviation(values)
          average = mean(values)
          sum = values.sum { |value| (value - average)**2 }
          (Math.sqrt(sum / values.length) * 1000).round / 1000.0
        end

        # takeByTopologyNUMAPacked.
        def take_by_topology_numa_packed(topology, available, count, strategy: PACKED, prefer_align_by_uncore_cache: false)
          acc = Accumulator.new(topology, available, count, strategy)
          return acc.result if acc.satisfied?
          raise Error, "not enough cpus available to satisfy request: requested=#{count}, available=#{available.size}" if acc.failed?

          acc.take_full_first_level
          return acc.result if acc.satisfied?

          acc.take_full_second_level
          return acc.result if acc.satisfied?

          if prefer_align_by_uncore_cache
            acc.take_uncore_cache
            return acc.result if acc.satisfied?
          end
          if strategy != SPREAD
            acc.take_full_cores
            return acc.result if acc.satisfied?
          end
          acc.take_remaining_cpus
          return acc.result if acc.satisfied?

          raise Error, "failed to allocate cpus"
        end

        # `cpus, _ := takeByTopologyNUMAPacked(...)`: an error is an empty set.
        def packed_or_empty(topology, available, count, strategy)
          take_by_topology_numa_packed(topology, available, count, strategy: strategy)
        rescue Error
          CPUSet.empty
        end

        # takeByTopologyNUMADistributed.
        def take_by_topology_numa_distributed(topology, available, count, group_size, strategy: PACKED)
          return take_by_topology_numa_packed(topology, available, count, strategy: strategy) unless (count % group_size).zero?

          acc = Accumulator.new(topology, available, count, strategy)
          return acc.result if acc.satisfied?
          raise Error, "not enough cpus available to satisfy request: requested=#{count}, available=#{available.size}" if acc.failed?

          numas = acc.sort_available_numa_nodes
          min_numas, max_numas = acc.numa_range(group_size)
          (min_numas..max_numas).each do |k|
            best_balance = Float::INFINITY
            best_remainder = nil
            best_combo = nil
            acc.iterate_combinations(numas, k) do |combo_slice|
              next :break if best_balance.zero?

              combo = combo_slice.to_a
              next :continue if acc.details.cpus_in_numa_nodes(*combo).size < count

              groups = combo.sum { |numa| acc.details.cpus_in_numa_nodes(numa).size / group_size }
              next :continue if groups * group_size < count

              distribution = (count / combo.length / group_size) * group_size
              next :continue if combo.any? { |numa| acc.details.cpus_in_numa_nodes(numa).size < distribution }

              after = numas.to_h { |numa| [numa, acc.details.cpus_in_numa_nodes(numa).size] }
              combo.each { |numa| after[numa] -= distribution }
              remainder = count - (distribution * combo.length)
              remainder_combo = combo.select { |numa| after[numa] >= group_size }

              best_local_balance = Float::INFINITY
              best_local_remainder = nil
              if remainder.zero?
                best_local_balance = standard_deviation(after.values)
                best_local_remainder = nil
              end
              subset_size = remainder_combo.length
              while remainder.positive? && subset_size >= 1
                acc.iterate_combinations(remainder_combo, subset_size) do |subset_slice|
                  subset = subset_slice.to_a
                  left = remainder
                  trial = after.dup
                  next :continue if subset.sum { |numa| trial[numa] } < left

                  while left.positive?
                    progressed = false
                    subset.each do |numa|
                      break if left.zero?
                      next if trial[numa] < group_size

                      trial[numa] -= group_size
                      left -= group_size
                      progressed = true
                    end
                    # Upstream would spin forever here; no subset can do it.
                    break unless progressed
                  end
                  next :continue if left.positive?

                  balance = standard_deviation(trial.values)
                  if balance < best_local_balance
                    best_local_balance = balance
                    best_local_remainder = subset_slice
                  end
                  :continue
                end
                subset_size -= 1
              end
              if best_local_balance < best_balance
                best_balance = best_local_balance
                best_remainder = best_local_remainder
                best_combo = combo_slice
              end
              :continue
            end
            next if best_combo.nil?

            chosen = best_combo.to_a
            distribution = (count / chosen.length / group_size) * group_size
            chosen.each do |numa|
              acc.take(packed_or_empty(topology, acc.details.cpus_in_numa_nodes(numa), distribution, strategy))
            end
            remainder = count - (distribution * chosen.length)
            remainder_numas = best_remainder ? best_remainder.to_a : []
            while remainder.positive?
              progressed = false
              remainder_numas.each do |numa|
                break if remainder.zero?
                next if acc.details.cpus_in_numa_nodes(numa).size < group_size

                acc.take(packed_or_empty(topology, acc.details.cpus_in_numa_nodes(numa), group_size, strategy))
                remainder -= group_size
                progressed = true
              end
              break unless progressed
            end
            raise Error, "accounting error, not enough CPUs allocated, remaining: #{acc.needed}" if acc.needed.positive?
            raise Error, "accounting error, too many CPUs allocated, remaining: #{acc.needed}" if acc.needed.negative?

            return acc.result
          end
          take_by_topology_numa_packed(topology, available, count, strategy: strategy)
        end
      end
    end
  end
end
