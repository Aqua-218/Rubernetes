# frozen_string_literal: true

require "digest"
require "securerandom"
require_relative "cgroup_v2"

module Rubernetes
  module Platform
    module Linux
      # The cgroupfs layout used by a native Linux node with cgroupsPerQOS.
      # Only the Pod directory uses the API UID. Each runtime generation owns
      # distinct leaves, so a stale sandbox can be released after its successor
      # has attached without confusing their journal or kernel identities.
      class KubeletCgroupLayout
        HIERARCHY = "kubepods"
        TIERS = %w[burstable besteffort].freeze
        UID = /\A[A-Za-z0-9-]{1,64}\z/
        LEAF = /\Arbn-([0-9a-f]{12})-([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\z/

        attr_reader :base

        def self.reservation_owner(node_name) = Digest::SHA256.hexdigest(node_name)[0, 24]

        def self.container_leaf_prefix(sandbox)
          return unless sandbox.is_a?(CgroupV2::Handle) && sandbox.container_id == "sandbox"

          match = LEAF.match(File.basename(sandbox.path))
          "rbn-#{match[1]}-" if match && match[2] == "sandbox"
        end

        def initialize(root, enabled: true)
          @base = File.join(File.expand_path(root), HIERARCHY)
          @enabled = enabled
        end

        def path(qos:, pod_id:, container_id:, pod_uid:, sandbox:)
          if sandbox
            raise CgroupV2::InvalidPath, "container leaf must not use the sandbox identity" if container_id == "sandbox"

            previous = handle(sandbox.path)
            return nil unless previous
            raise CgroupV2::InvalidPath, "cgroup sandbox identity changed" unless previous.pod_id == pod_id && previous.container_id == "sandbox"

            parent = File.dirname(previous.path)
            generation = pod_id.split("-").last
          else
            return nil unless @enabled && pod_uid.is_a?(String) && UID.match?(pod_uid)

            pod = "pod#{pod_uid}"
            generation = pod_id.delete_prefix("#{pod}-")
            return nil unless /\A[0-9a-f]{12}\z/.match?(generation)

            parent = File.join(qos_path(qos), pod)
          end

          File.join(parent, "rbn-#{generation}-#{container_id}")
        end

        def tier_paths = TIERS.map { |tier| qos_path(tier) }

        def lock_tier(target, create: false)
          tier = File.dirname(target, 2)
          FileUtils.mkdir_p(tier) if create
          File.open(tier, File::RDONLY) do |file|
            file.flock(File::LOCK_EX)
            begin
              yield
            ensure
              # Another thread can fork a holder while the descriptor is
              # open. Closing the parent's descriptor alone keeps its lock.
              file.flock(File::LOCK_UN)
            end
          end
        end

        # A Pod must have its cgroup before image resolution. Hold an empty
        # child while startup can still fail or be cancelled. That child keeps
        # another sandbox generation from removing the parent in the meantime.
        def with_reservation(uid, qos, owner)
          return yield unless uid.is_a?(String) && UID.match?(uid)

          parent = File.join(qos_path(qos), "pod#{uid}")
          reservation = File.join(parent, "rbn-pending-#{owner}-#{SecureRandom.hex(6)}")
          lock_tier(reservation) { FileUtils.mkdir_p(reservation) }
          yield
        ensure
          release_reservation(reservation) if reservation
        end

        # A killed agent cannot run the ensure block. Reclaim only reservations
        # of this worker before its next Pod sync. Never touch a workload leaf.
        def clear_reservations(owner)
          CgroupV2::QOS_CLASSES.each do |qos|
            Dir.glob(File.join(qos_path(qos), "pod*", "rbn-pending-#{owner}-*")).each do |path|
              next unless UID.match?(File.basename(File.dirname(path)).delete_prefix("pod"))
              next unless File.basename(path).match?(/\Arbn-pending-[0-9a-f]{24}-[0-9a-f]{12}\z/)

              release_reservation(path)
            end
          end
        end

        def handle(path)
          return nil unless path.start_with?("#{@base}/")

          components = path.delete_prefix("#{@base}/").split("/")
          qos = (TIERS.include?(components.first) ? components.shift : "guaranteed")
          return nil unless components.length == 2

          pod, leaf = components
          match = LEAF.match(leaf)
          return nil unless pod.start_with?("pod") && UID.match?(pod.delete_prefix("pod")) && match

          container_id = match[2]
          pod_id = "#{pod}-#{match[1]}"
          identity = container_id == "sandbox" ? "cgroup:#{pod_id}" : "cgroup:#{pod_id}:#{container_id}"
          CgroupV2::Handle.new(path: path, qos: qos, pod_id: pod_id, container_id: container_id, identity: identity)
        end

        def handles
          CgroupV2::QOS_CLASSES.flat_map do |qos|
            Dir.glob(File.join(qos_path(qos), "pod*", "rbn-*")).filter_map do |path|
              handle(path) if File.directory?(path)
            end
          end
        end

        private

        def release_reservation(path)
          lock_tier(path) do
            Dir.rmdir(path)
            parent = File.dirname(path)
            next if Dir.children(parent).any? { |name| File.directory?(File.join(parent, name)) }

            begin
              Dir.rmdir(parent)
            rescue Errno::ENOTEMPTY
              # Another reservation or the attached sandbox owns the parent.
              nil
            end
          end
        rescue Errno::ENOENT
          nil
        end

        def qos_path(qos)
          qos == "guaranteed" ? @base : File.join(@base, qos)
        end
      end
    end
  end
end
