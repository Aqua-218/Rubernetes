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
          inventory = claims
          holders = inventory.select { |claim| claim["kind"] == "namespace" }.to_h { |claim| [claim["owner"], claim] }
          inventory.filter_map { |claim| observe(claim, holders[claim["owner"]]) }
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

        def observe(claim, holder)
          metadata = claim["metadata"].is_a?(Hash) ? claim["metadata"] : {}
          case claim["kind"].to_s
          when "process" then observe_process(claim, metadata)
          when "namespace" then observe_namespace(claim, metadata)
          when "workspace" then observe_workspace(claim, metadata, holder)
          when "cgroup", "mount" then observe_path(claim, metadata)
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

          # The pid with this start time is the claimed process: a reused pid
          # never carries the old start time within one boot.  Its executable
          # is not evidence either way.  The digest recorded at start is of
          # the file the workload was started from, and a workload that execs
          # (a shell entrypoint ending in `exec tini ...`, as every GitLab
          # image does) runs another one from then on.  Treating that as pid
          # reuse made an agent restart discard every such running Pod.
          entry(claim, metadata.merge(
            "live" => true,
            "observed_start_time" => observed_start,
            "cgroup_membership" => read_link_or_file("#{proc_root}/#{pid}/cgroup"),
            "pid_namespace" => namespace_link(pid, "pid"),
            "mount_namespace" => namespace_link(pid, "mnt")
          ))
        end

        def process_start_time(pid)
          tail = process_stat(pid)
          return nil if tail.nil? || %w[Z X].include?(tail.first)

          tail[19]
        end

        def process_stat(pid)
          stat = read_file("#{proc_root}/#{pid}/stat")
          return unless stat

          # The comm field may contain spaces and parentheses, so field 22 is
          # counted from after the final ')'.
          stat[((stat.rindex(")") || -1) + 1)..].to_s.split
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
            expected_start = kernel["start_time"] || metadata["start_time"]
            if expected_start
              started = process_start_time(pid)
              return nil unless started
              return reuse_entry(claim, metadata, observed_start_time: started) unless started.to_s == expected_start.to_s
            end
            observed = links.keys.to_h { |name| [name, namespace_link(pid, name)] }
            return nil if observed.values.all?(&:nil?) || (expected_start && process_start_time(pid).nil?)
            return reuse_entry(claim, metadata, observed_links: observed) if observed != links

            return entry(claim, metadata.merge("live" => true, "observed_namespace_links" => observed))
          end

          observe_path(claim, metadata)
        end

        def namespace_link(pid, name)
          proc_name = Platform::Linux::Setns::NAMESPACE_TYPES[name.to_sym]&.last || name
          readlink("#{proc_root}/#{pid}/ns/#{proc_name}")
        end

        # --------------------------------------------------------------- path

        def observe_workspace(claim, metadata, holder)
          root = metadata["root"]
          return observe_path(claim, metadata) if root.to_s.empty?

          path = observe_path(claim, metadata.merge(metadata["root_identity"] || {}).merge("path" => root))
          return path unless path && path["identity"] == claim["identity"]
          return unmounted_workspace(path, holder) unless metadata["mounted"] == true

          expected = metadata["mount_identity"]
          return observe_unverifiable(claim, metadata) unless expected.is_a?(Hash) && holder

          kernel = holder.fetch("metadata", {})
          observed = observe_namespace(holder, kernel)
          return nil unless observed
          return observe_unverifiable(claim, metadata) unless observed["identity"] == holder["identity"]

          pid = kernel.dig("kernel_identity", "pid") || kernel["pid"]
          readback = read_file("#{proc_root}/#{Integer(pid)}/mountinfo")
          return observe_unverifiable(claim, metadata) unless readback

          compare_workspace_mount(claim, metadata, expected, readback)
        end

        # An unmounted workspace is a directory tree the kernel holds no
        # reference to.  It is in use only while its sandbox's namespaces
        # are; once those are gone it is what a dead operation left on disk.
        # Calling it live because the directory exists wedged recovery: an
        # agent restarted after its sandboxes died refused to start.
        def unmounted_workspace(path, holder)
          return path if holder && observe_namespace(holder, holder.fetch("metadata", {}))

          path.merge("metadata" => path.fetch("metadata").merge("live" => false))
        end

        def compare_workspace_mount(claim, metadata, expected, readback)
          target = metadata.fetch("root").gsub(/[\\ \t\n]/) { |character| format("\\%03o", character.ord) }
          matches = readback.lines.filter_map do |line|
            mount, details = line.split(" - ", 2)
            fields = mount.split
            [fields.first, details&.split&.first] if fields[4] == target
          end
          return nil if matches.empty?

          unless matches == [[expected.fetch("mount_id").to_s, expected.fetch("filesystem")]] && expected["mountpoint"] == metadata["root"]
            return reuse_entry(claim, metadata, observed_mounts: matches)
          end

          entry(claim, metadata.merge("live" => true))
        end

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
