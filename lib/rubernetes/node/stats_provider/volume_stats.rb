# frozen_string_literal: true

module Rubernetes
  module Node
    class StatsProvider
      # Kubelet's filesystem resource analyzer. The sampler is independent of
      # Summary and Prometheus requests, which use the same published samples.
      module VolumeStats
        VolumeSample = Data.define(:sandbox_id, :mounts, :entries)
        EMPTY_VOLUMES = [].freeze

        def start_volume_stats(error_handler: nil)
          return unless @volume_period.positive?

          @volume_mutex.synchronize do
            return if @volume_stopped || @volume_thread&.alive?

            @volume_error_handler = error_handler
            @volume_thread = Thread.new { run_volume_stats }
          end
        end

        def stop_volume_stats
          thread = @volume_mutex.synchronize do
            @volume_stopped = true
            @volume_samples = {}
            @volume_condition.broadcast
            @volume_thread
          end
          return if @volume_collection_lock.owned?

          thread&.join unless thread == Thread.current
          @volume_collection_lock.synchronize do
            @volume_mutex.synchronize { @volume_thread = nil }
          end
        end

        # Also used by the agent's deterministic run_once entry point.
        def sample_volume_stats
          return unless @volume_period.positive? && @volume_collection_lock.try_lock

          begin
            return unless @volume_mutex.synchronize { !@volume_stopped && @monotonic.call >= @next_volume_sample }

            samples = collect_pod_volumes
            @volume_mutex.synchronize do
              @volume_samples = samples unless @volume_stopped
              @next_volume_sample = @monotonic.call + @volume_period
            end
          ensure
            @volume_collection_lock.unlock
          end
        end

        private

        def initialize_volume_stats(period)
          @volume_period = Float(period)
          raise ArgumentError, "volume_stats_agg_period must be finite" unless @volume_period.finite?

          @volume_mutex = Mutex.new
          @volume_collection_lock = Mutex.new
          @volume_condition = ConditionVariable.new
          @volume_samples = {}
          @next_volume_sample = -Float::INFINITY
          @volume_stopped = false
        end

        def run_volume_stats
          loop do
            break if volume_stats_stopped?

            begin
              sample_volume_stats
            rescue StandardError => error
              @volume_error_handler&.call(error, :volume_stats)
            end
            @volume_mutex.synchronize { @volume_condition.wait(@volume_mutex, @volume_period) unless @volume_stopped }
          end
        end

        def volume_stats_stopped?
          @volume_mutex.synchronize { @volume_stopped }
        end

        def collect_pod_volumes
          running_stats_records.each_with_object({}) do |record, result|
            break result if volume_stats_stopped?

            mounts = volume_mounts(record)
            next if mounts.nil? || mounts.empty?

            pod = record[:pod] || {}
            specs = Array(pod.dig("spec", "volumes")).to_h { |volume| [volume["name"], volume] }
            entries = mounts.filter_map do |name, mount|
              break [] if volume_stats_stopped?

              collect_volume(pod, name.to_s, mount, specs.fetch(name.to_s, {}))
            end
            result[record[:uid].to_s] = VolumeSample.new(record[:sandbox_id], mounts, entries)
          end
        end

        def volume_mounts(record)
          handle = record[:volume]
          handle["mounts"] if handle.is_a?(Hash)
        end

        def pod_volume_stats(record, snapshot)
          sample = snapshot[record[:uid].to_s]
          return EMPTY_VOLUMES unless sample && sample.sandbox_id == record[:sandbox_id]

          mounts = volume_mounts(record)
          same_mount = @has_stats_records ? sample.mounts.equal?(mounts) : sample.mounts == mounts
          same_mount ? Helpers.deep_copy(sample.entries) : EMPTY_VOLUMES
        end

        def collect_volume(pod, name, mount, spec)
          return if spec["hostPath"] || spec["gitRepo"] # Both implement MetricsNil.

          path = mount["path"] if mount.is_a?(Hash)
          return if path.nil? || !File.exist?(path)

          stamp = @clock.call.utc.iso8601
          started = @monotonic.call
          stats = csi_volume_stats(mount["id"], path, stamp, pod: pod, name: name)
          return if stats == :unsupported

          source = stats ? "csi" : "fs"
          if !stats && File.directory?(path)
            usage = @project_quota_usage&.call(mount["id"], path) || DirectoryUsage.measure(path)
            stats = directory_stats(path, stamp, device: path, usage: usage)
          end
          observe_volume_collection(source, @monotonic.call - started)
          return unless stats

          entry = stats.merge("name" => name)
          claim = spec.dig("persistentVolumeClaim", "claimName")
          claim = "#{pod.dig("metadata", "name")}-#{name}" if spec["ephemeral"]
          entry["pvcRef"] = {"name" => claim, "namespace" => pod.dig("metadata", "namespace").to_s} if claim
          entry
        rescue SystemCallError
          nil # A mount can disappear during a sample.
        end

        def csi_volume_stats(id, path, stamp, pod:, name:)
          return nil if @volume_stats.nil? || id.nil?

          value = begin
            @volume_stats.call(id, path)
          rescue StandardError => error
            @volume_error_handler&.call(error, :volume_stats)
            :unsupported
          end
          return value if value.nil? || value == :unsupported

          record_volume_health(pod, name, value) if @volume_health
          stats = {"time" => stamp}.merge(value.slice("availableBytes", "capacityBytes", "usedBytes", "inodesFree", "inodes", "inodesUsed")).compact
          condition = value["volumeCondition"]
          stats["volumeHealthStats"] = {"abnormal" => Helpers.key(condition, "abnormal", false) == true} if @volume_health && condition.is_a?(Hash)
          stats
        end

        def record_volume_health(pod, name, stats)
          condition = stats["volumeCondition"]
          return unless Helpers.key(condition, "abnormal", false) == true

          @event_recorder&.record(involved_object: pod, reason: "VolumeConditionAbnormal", type: "Warning",
                                  message: "Volume #{name}: #{Helpers.key(condition, "message", "")}")
        end

        def observe_volume_collection(source, seconds)
          @metrics_observer&.call(source, seconds)
        rescue StandardError => error
          @volume_error_handler&.call(error, :volume_metrics)
        end
      end
    end
  end
end
