# frozen_string_literal: true

require "digest"

module Rubernetes
  module Runtime
    class Native
      # Independently collected kernel inventory for native-profile recovery.
      #
      # After a crash the in-process bookkeeping is gone and the durable
      # ownership ledger is only a *claim* about what the kernel holds.  This
      # observer re-reads the kernel for every claim and reports what is
      # actually there, so Support::Recovery can tell three cases apart:
      #
      #   * the object is present and its identity evidence still matches --
      #     reported live, and adoption may continue;
      #   * the object is gone -- omitted from the inventory, which Recovery
      #     reads as dead and may release;
      #   * the object is present but the evidence differs (a reused pid, a
      #     recreated directory, a re-made cgroup) -- reported with a *different*
      #     identity, which Recovery must treat as reuse evidence and refuse to
      #     clean automatically.
      #
      # It never consults the runtime's in-memory state: that is the whole
      # point of `external_observer?` being true here and false for the
      # in-process inventory callback.
      class KernelObserver
        PROCESS_EVIDENCE_FIELDS = %w[workload_start_time start_time].freeze
        MISMATCH_SUFFIX = "#observed-mismatch"

        def initialize(ledger:, proc_root: "/proc", io: File)
          @ledger = ledger
          @proc_root = proc_root
          @io = io
        end

        # Recovery refuses to release durable ownership unless the observer
        # says it reads the kernel rather than process memory.
        def external_observer?
          true
        end

        def list_resources
          claims.filter_map { |claim| observe(claim) }
        end
        alias resources list_resources
        alias observe_resources list_resources

        def call
          list_resources
        end

        private

        attr_reader :ledger, :proc_root, :io

        def claims
          ledger.resources(include_released: false).map { |claim| stringify(claim) }
        end

        def observe(claim)
          metadata = claim["metadata"].is_a?(Hash) ? claim["metadata"] : {}
          case claim["kind"].to_s
          when "process" then observe_process(claim, metadata)
          when "namespace" then observe_namespace(claim, metadata)
          when "cgroup", "workspace", "mount" then observe_path(claim, metadata)
          else observe_unverifiable(claim, metadata)
          end
        end

        # ------------------------------------------------------------ process

        def observe_process(claim, metadata)
          pid = integer(metadata["workload_pid"] || metadata["pid"])
          return nil if pid.nil?

          observed_start = process_start_time(pid)
          return nil if observed_start.nil?

          recorded_start = PROCESS_EVIDENCE_FIELDS.filter_map { |field| metadata[field] }.first
          if recorded_start.nil? || recorded_start.to_s != observed_start.to_s
            # The pid exists but belongs to a different process than the one the
            # ledger claims: pid reuse, never a dead resource to clean up.
            return reuse_entry(claim, metadata, observed_start_time: observed_start)
          end

          digest = metadata["workload_executable_digest"] || metadata["executable_digest"]
          # The ledger records "sha256:<hex>"; the observation is the bare hex.
          # Comparing them as-is reported every live workload as pid reuse, so an
          # agent restarted with running Pods refused to start (RecoveryRequired).
          if digest && (observed = executable_digest(pid)) && observed != digest.to_s.delete_prefix("sha256:")
            return reuse_entry(claim, metadata, observed_start_time: observed_start, observed_digest: observed)
          end

          entry(claim, metadata.merge(
            "live" => true,
            "observed_start_time" => observed_start,
            "cgroup_membership" => read_link_or_file("#{proc_root}/#{pid}/cgroup"),
            "pid_namespace" => namespace_link(pid, "pid"),
            "mount_namespace" => namespace_link(pid, "mnt")
          ))
        end

        def process_start_time(pid)
          stat = read_file("#{proc_root}/#{pid}/stat")
          return nil if stat.nil?

          # The comm field may contain spaces and parentheses, so field 22 is
          # counted from after the final ')'.
          tail = stat[(stat.rindex(")") || -1) + 1..].to_s.split
          tail[19]
        end

        def executable_digest(pid)
          path = "#{proc_root}/#{pid}/exe"
          target = readlink(path)
          return nil if target.nil? || target.end_with?(" (deleted)")

          content = read_binary(path)
          content && Digest::SHA256.hexdigest(content)
        end

        # ---------------------------------------------------------- namespace

        def observe_namespace(claim, metadata)
          # The sandbox records its namespaces' kernel evidence under
          # kernel_identity; looking only at the top level reported every
          # namespace as unverifiable, and Recovery then handed a dead one to a
          # cleaner that no longer knew it.
          kernel = metadata["kernel_identity"].is_a?(Hash) ? metadata["kernel_identity"] : {}
          links = metadata["namespace_links"] || kernel["namespace_links"]
          links = links.is_a?(Hash) ? links.transform_keys(&:to_s) : nil
          pid = integer(metadata["pid"] || metadata["workload_pid"] || metadata["supervisor_pid"] || kernel["pid"])

          if links && pid
            observed = links.keys.to_h { |name| [name, namespace_link(pid, name)] }
            return nil if observed.values.all?(&:nil?)
            return reuse_entry(claim, metadata, observed_links: observed) if observed != links

            return entry(claim, metadata.merge("live" => true, "observed_namespace_links" => observed))
          end

          observe_path(claim, metadata)
        end

        def namespace_link(pid, name)
          readlink("#{proc_root}/#{pid}/ns/#{name}")
        end

        # --------------------------------------------------------------- path

        def observe_path(claim, metadata)
          path = metadata["path"]
          return observe_unverifiable(claim, metadata) if path.nil? || path.to_s.empty?

          stat = stat_path(path)
          return nil if stat.nil?

          recorded_inode = metadata["inode"] || metadata["cgroup_inode"]
          recorded_device = metadata["device"]
          if recorded_inode && recorded_inode.to_s != stat.fetch(:inode).to_s
            return reuse_entry(claim, metadata, observed_inode: stat.fetch(:inode), observed_device: stat.fetch(:device))
          end
          if recorded_device && recorded_device.to_s != stat.fetch(:device).to_s
            return reuse_entry(claim, metadata, observed_inode: stat.fetch(:inode), observed_device: stat.fetch(:device))
          end

          # A cgroup is in use while it holds processes; an empty one left by
          # a dead operation is removable (rmdir refuses a populated one anyway).
          live = claim["kind"].to_s == "cgroup" ? cgroup_populated?(path) : true
          entry(claim, metadata.merge("live" => live,
                                      "observed_inode" => stat.fetch(:inode),
                                      "observed_device" => stat.fetch(:device)))
        end

        # cgroup.events "populated"; unknown counts as populated.
        def cgroup_populated?(path)
          events = read_file(File.join(path.to_s, "cgroup.events"))
          return true if events.nil?

          line = events.lines.find { |entry| entry.start_with?("populated ") }
          line.nil? || line.split.last != "0"
        end

        def stat_path(path)
          stat = io.stat(path.to_s)
          {device: stat.dev, inode: stat.ino}
        rescue SystemCallError
          nil
        end

        # ------------------------------------------------------ unverifiable

        # A claim whose metadata carries no kernel evidence cannot be confirmed
        # *or* denied from outside the process.  Reporting it as absent would
        # invite Recovery to release ownership on no evidence at all, so it is
        # reported present-but-not-live: never adopted, never auto-cleaned.
        def observe_unverifiable(claim, metadata)
          entry(claim, metadata.merge("live" => false, "unverifiable" => true))
        end

        # -------------------------------------------------------------- shape

        def entry(claim, metadata)
          {
            "kind" => claim["kind"].to_s,
            "id" => claim["id"].to_s,
            "identity" => claim["identity"].to_s,
            "owner" => claim["owner"].to_s,
            "metadata" => metadata.merge("managed_by" => "rubernetes-native",
                                         "observer" => "kernel")
          }
        end

        # Deliberately reports an identity that cannot equal the claim, so the
        # mismatch is fatal to automatic cleanup rather than being mistaken for
        # a dead resource.
        def reuse_entry(claim, metadata, **observed)
          evidence = observed.map { |key, value| "#{key}=#{value}" }.sort.join(",")
          entry(claim, metadata.merge("live" => true, "identity_mismatch" => true,
                                      "observed_evidence" => evidence))
            .merge("identity" => "#{claim["identity"]}#{MISMATCH_SUFFIX}(#{evidence})")
        end

        def stringify(value)
          hash = value.respond_to?(:to_h) ? value.to_h : value
          hash.each_with_object({}) do |(key, entry_value), result|
            result[key.to_s] = entry_value.is_a?(Hash) ? entry_value.transform_keys(&:to_s) : entry_value
          end
        end

        def integer(value)
          Integer(value)
        rescue ArgumentError, TypeError
          nil
        end

        def read_file(path)
          io.read(path)
        rescue SystemCallError, IOError
          nil
        end

        def read_binary(path)
          io.binread(path)
        rescue SystemCallError, IOError
          nil
        end

        def read_link_or_file(path)
          read_file(path)
        end

        def readlink(path)
          io.readlink(path)
        rescue SystemCallError, IOError, NotImplementedError
          nil
        end
      end
    end
  end
end
