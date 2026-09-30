# frozen_string_literal: true

require "fileutils"
require "json"
require_relative "cpu_set"

module Rubernetes
  module Node
    module CPUManager
      # pkg/kubelet/cm/cpumanager/state: the default (shared) CPU set and
      # the exclusive assignments, pod UID => container => CPUSet.
      class MemoryState
        def initialize
          @mutex = Mutex.new
          @assignments = {}
          @pod_cpu_sets = {}
          @default = CPUSet.empty
        end

        # PodLevelResourceManagers: the CPUs a Pod with pod-level resources
        # holds as a whole (its containers' sets are carved from it).
        def pod_cpu_set(pod_uid) = @mutex.synchronize { @pod_cpu_sets[pod_uid.to_s] }
        def pod_cpu_sets = @mutex.synchronize { @pod_cpu_sets.dup }

        def set_pod_cpu_set(pod_uid, cpus)
          @mutex.synchronize { @pod_cpu_sets[pod_uid.to_s] = cpus }
          changed
        end

        # DeletePod: every assignment of the Pod, pod-level included.
        def delete_pod(pod_uid)
          @mutex.synchronize do
            @pod_cpu_sets.delete(pod_uid.to_s)
            @assignments.delete(pod_uid.to_s)
          end
          changed
        end

        def cpu_set(pod_uid, container) = @mutex.synchronize { @assignments.dig(pod_uid.to_s, container.to_s) }
        def default_cpu_set = @mutex.synchronize { @default }

        # GetCPUSetOrDefault.
        def cpu_set_or_default(pod_uid, container) = cpu_set(pod_uid, container) || default_cpu_set

        def assignments = @mutex.synchronize { @assignments.transform_values(&:dup) }

        def set_cpu_set(pod_uid, container, cpus)
          @mutex.synchronize { (@assignments[pod_uid.to_s] ||= {})[container.to_s] = cpus }
          changed
        end

        def default_cpu_set=(cpus)
          @mutex.synchronize { @default = cpus }
          changed
        end

        def assignments=(value)
          @mutex.synchronize do
            @assignments = value.to_h do |pod, containers|
              [pod.to_s, containers.to_h do |name, cpus|
                [name.to_s, cpus]
              end]
            end
          end
          changed
        end

        def delete(pod_uid, container)
          @mutex.synchronize do
            containers = @assignments[pod_uid.to_s]
            containers&.delete(container.to_s)
            @assignments.delete(pod_uid.to_s) if containers && containers.empty?
          end
          changed
        end

        def clear_state
          @mutex.synchronize do
            @default = CPUSet.empty
            @assignments = {}
            @pod_cpu_sets = {}
          end
          changed
        end

        private

        def changed = nil
      end

      # state_checkpoint.go: the memory state mirrored to
      # <state dir>/cpu_manager_state in the upstream V3 checkpoint format,
      # so the file reads the same as a kubelet's (checksum included).
      class CheckpointState < MemoryState
        FILE = "cpu_manager_state"

        class Error < StandardError; end

        attr_reader :path

        # +pod_level+: PodLevelResourceManagers, which writes the V3
        # checkpoint (podEntries) and checksums it as such.
        def initialize(directory:, policy_name:, file: FILE, pod_level: false)
          super()
          @path = File.join(directory, file)
          @policy_name = policy_name.to_s
          @pod_level = pod_level
          restore
        end

        # The checkpoint JSON (json.Marshal of CPUManagerCheckpoint).
        def self.encode(policy_name, default_cpu_set, assignments, pod_cpu_sets: nil)
          entries = assignments.sort.to_h { |pod, containers| [pod, containers.sort.to_h { |name, cpus| [name, cpus.to_s] }] }
          pods = pod_cpu_sets&.sort&.to_h { |pod, cpus| [pod, {"cpuSet" => cpus.to_s}] }
          checksum = Checksum.fnv32a(Checksum.for_hash(policy_name, default_cpu_set.to_s, entries,
                                                       pod_entries: pods.nil? ? :absent : pods))
          body = {"policyName" => policy_name, "defaultCpuSet" => default_cpu_set.to_s}
          body["entries"] = entries unless entries.empty?
          body["podEntries"] = pods unless pods.nil? || pods.empty?
          body["checksum"] = checksum
          JSON.generate(body)
        end

        private

        def changed
          FileUtils.mkdir_p(File.dirname(@path))
          temporary = "#{@path}.tmp.#{Process.pid}"
          File.write(temporary, self.class.encode(@policy_name, @default, @assignments, pod_cpu_sets: @pod_level ? @pod_cpu_sets : nil))
          File.rename(temporary, @path)
        end

        # tryRestoreState: an absent file starts empty (and is written); a
        # file for another policy, or with a bad checksum, is refused.
        def restore
          unless File.exist?(@path)
            changed
            return
          end

          body = JSON.parse(File.read(@path))
          entries = body["entries"] || {}
          accepted = Checksum.accepted(body["policyName"].to_s, body["defaultCpuSet"].to_s, entries, body["podEntries"])
          # A zero checksum (a V1 checkpoint that never had one) is not checked.
          if body["checksum"].to_i.nonzero? && !accepted.include?(body["checksum"].to_i)
            raise Error, "checkpoint is corrupted: checksum #{body["checksum"]} does not match #{accepted.first}"
          end
          if body["policyName"].to_s != @policy_name
            raise Error, "configured policy \"#{@policy_name}\" differs from state checkpoint policy \"#{body["policyName"]}\""
          end

          @default = CPUSet.parse(body["defaultCpuSet"])
          @assignments = entries.to_h do |pod, containers|
            [pod, containers.to_h { |name, cpus| [name, CPUSet.parse(cpus)] }]
          end
          @pod_cpu_sets = (body["podEntries"] || {}).to_h { |pod, entry| [pod, CPUSet.parse(entry["cpuSet"].to_s)] }
        rescue JSON::ParserError, CPUSet::ParseError => error
          raise Error, "could not restore state from checkpoint: #{error.message}"
        end
      end

      # checkpointmanager/checksum: FNV-32a over go-spew's "%#v" rendering
      # of the checkpoint struct (dump.ForHash: sorted keys, types on
      # fields, none inside maps).  With PodLevelResourceManagers off the
      # kubelet writes the V2 struct (no PodEntries), hashed under the V3
      # type name; a V3 checkpoint (PodEntries) is accepted on restore.
      module Checksum
        module_function

        def for_hash(policy_name, default_cpu_set, entries, type_name: "CPUManagerCheckpoint", pod_entries: :absent)
          rendered_entries = spew_map(entries) { |containers| spew_map(containers) { |cpus| cpus.to_s } }
          pods = ""
          unless pod_entries == :absent
            rendered = spew_map(pod_entries || {}) { |entry| "{CPUSet:(cpuset.CPUSet)#{spew_cpuset(entry["cpuSet"])}}" }
            pods = " PodEntries:(state.PodCPUAssignments)#{rendered}"
          end
          "(*state.#{type_name}){PolicyName:(string)#{policy_name} DefaultCPUSet:(string)#{default_cpu_set} " \
            "Entries:(map[string]map[string]string)#{rendered_entries}#{pods} Checksum:(checksum.Checksum)0}"
        end

        # Every checksum a kubelet could have written for this content.
        def accepted(policy_name, default_cpu_set, entries, pod_entries)
          candidates = [for_hash(policy_name, default_cpu_set, entries),
                        for_hash(policy_name, default_cpu_set, entries, type_name: "CPUManagerCheckpointV2"),
                        for_hash(policy_name, default_cpu_set, entries, pod_entries: pod_entries)]
          candidates.map { |text| fnv32a(text) }
        end

        def spew_map(map)
          "map[#{map.sort.map { |key, value| "#{key}:#{yield(value)}" }.join(" ")}]"
        end

        # A cpuset.CPUSet struct as spew renders it: its unexported elems map.
        def spew_cpuset(text)
          ids = CPUSet.parse(text.to_s).to_a
          "{elems:(map[int]struct {})map[#{ids.map { |id| "#{id}:{}" }.join(" ")}]}"
        end

        def fnv32a(text)
          text.to_s.each_byte.reduce(2_166_136_261) { |hash, byte| ((hash ^ byte) * 16_777_619) & 0xffffffff }
        end
      end
    end
  end
end
