# frozen_string_literal: true

require "find"
require "thread"

require_relative "../image/reference"

module Rubernetes
  module Node
    # pkg/kubelet/images/image_gc_manager.go (v1.36.2) over the image
    # resolver's cache of unpacked images.  That cache used to grow for the
    # life of the agent: every image a Pod ever ran stayed unpacked on disk.
    #
    # Every pass (ImageGCPeriod, 5 minutes) detects the cached images --
    # firstDetected on first sight, lastUsed while a Pod on the node uses
    # one -- and, when the image filesystem is at or above
    # imageGCHighThresholdPercent (85), deletes unused images oldest-used
    # first until usage is down to imageGCLowThresholdPercent (80).  An image
    # detected less than imageMinimumGCAge (2 minutes) ago is kept, and so is
    # one handed out to a starting Pod since the pass began.  With
    # imageMaximumGCAge set, unused images older than it go first whatever
    # the usage.  DeleteUnusedImages (delete_unused_images) is the eviction
    # manager's node-level reclaim for nodefs/imagefs.
    class ImageGCManager
      PERIOD_SECONDS = 300.0
      DEFAULT_HIGH_THRESHOLD_PERCENT = 85
      DEFAULT_LOW_THRESHOLD_PERCENT = 80
      DEFAULT_MIN_AGE = 120.0

      Record = Struct.new(:first_detected, :last_used, :size)

      class Error < StandardError; end

      # +resolver+: #cached_images and #evict_cached_image (Image::Resolver).
      # +fs_stats+: -> {"capacityBytes", "availableBytes"} of the image filesystem.
      # +pods+: -> the Pods whose containers are on the node.
      def initialize(resolver:, fs_stats:, pods:, high_threshold_percent: DEFAULT_HIGH_THRESHOLD_PERCENT,
                     low_threshold_percent: DEFAULT_LOW_THRESHOLD_PERCENT, min_age: DEFAULT_MIN_AGE, max_age: 0,
                     recorder: nil, node_ref: nil, monotonic: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                     sleeper: ->(seconds) { sleep(seconds) }, error_handler: nil, size_of: nil)
        high = Integer(high_threshold_percent)
        low = Integer(low_threshold_percent)
        raise ArgumentError, "invalid HighThresholdPercent #{high}, must be in range [0-100]" unless (0..100).cover?(high)
        raise ArgumentError, "invalid LowThresholdPercent #{low}, must be in range [0-100]" unless (0..100).cover?(low)
        raise ArgumentError, "LowThresholdPercent #{low} can not be higher than HighThresholdPercent #{high}" if low > high

        @resolver = resolver
        @fs_stats = fs_stats
        @pods = pods
        @high = high
        @low = low
        @min_age = Float(min_age)
        @max_age = Float(max_age)
        @recorder = recorder
        @node_ref = node_ref
        @monotonic = monotonic
        @sleeper = sleeper
        @error_handler = error_handler
        @size_of = size_of || method(:directory_size)
        @records = {}
        @mutex = Mutex.new
        @began = @monotonic.call
        @thread = nil
        @stop = false
      end

      # ->(reason) for every image freed: "age" or "space"
      # (kubelet_image_garbage_collected_total).
      attr_accessor :on_collected

      def records
        @mutex.synchronize { @records.transform_values(&:dup) }
      end

      # GarbageCollect: the keys deleted.
      def garbage_collect
        free_time = @monotonic.call
        images = images_in_eviction_order(free_time)
        freed_keys, images = free_old_images(images, free_time)
        stats = @fs_stats.call || {}
        capacity = stats["capacityBytes"].to_i
        available = [stats["availableBytes"].to_i, capacity].min
        if capacity.zero?
          event("Warning", "InvalidDiskCapacity", "invalid capacity 0 on image filesystem")
          raise Error, "invalid capacity 0 on image filesystem"
        end

        usage_percent = 100 - (available * 100 / capacity)
        return freed_keys if usage_percent < @high

        amount = capacity * (100 - @low) / 100 - available
        deleted, freed = free_space(amount, free_time, images)
        freed_keys += deleted
        if freed < amount
          message = "Insufficient free disk space on the node's image filesystem (#{usage_percent}% of #{format_size(capacity)} used). " \
                    "Failed to free sufficient space by deleting unused images (freed #{freed} bytes). " \
                    "Investigate disk usage, as it could be used by active images, logs, volumes, or other data."
          event("Warning", "FreeDiskSpaceFailed", message)
          raise Error, message
        end
        freed_keys
      end

      # DeleteUnusedImages: every unused image past its minimum age.
      def delete_unused_images
        free_time = @monotonic.call
        free_space(Float::INFINITY, free_time, images_in_eviction_order(free_time)).first
      end

      def start(interval: PERIOD_SECONDS)
        @mutex.synchronize do
          return self if @thread&.alive?

          @stop = false
          @thread = Thread.new do
            until @mutex.synchronize { @stop }
              begin
                garbage_collect
              rescue StandardError => error
                @error_handler&.call(error, :image_gc)
              end
              @sleeper.call(interval) unless @mutex.synchronize { @stop }
            end
          end
        end
        self
      end

      def stop
        thread = @mutex.synchronize do
          @stop = true
          @thread
        end
        thread&.wakeup rescue nil
        thread&.join(5) unless thread == Thread.current
        self
      end

      private

      # detectImages + imagesInEvictionOrder: unused images, least recently
      # used first, then earliest detected.
      def images_in_eviction_order(now)
        in_use = images_in_use
        cached = @resolver.cached_images
        @mutex.synchronize do
          current = cached.map(&:first)
          @records.delete_if { |key, _| !current.include?(key) }
          cached.each do |key, image, last_handed_out|
            record = (@records[key] ||= Record.new(now, nil, nil))
            record.last_used = [record.last_used, last_handed_out].compact.max
            record.last_used = now if in_use.include?(reference_of(key))
            record.size ||= image_size(image)
          end
          @records.reject { |key, _| in_use.include?(reference_of(key)) }
                  .sort_by { |key, record| [record.last_used || -Float::INFINITY, record.first_detected, key] }
        end
      end

      def free_old_images(images, free_time)
        return [[], images] if @max_age.zero? || free_time - @began <= @max_age

        deleted = []
        remaining = images.reject do |key, record|
          next false unless free_time - (record.last_used || record.first_detected) > @max_age

          freed = free_image(key, free_time, "age")
          deleted << key if freed
          freed
        end
        [deleted, remaining]
      end

      def free_space(bytes_to_free, free_time, images)
        freed = 0
        deleted = []
        images.each do |key, record|
          next if record.last_used && record.last_used >= free_time
          next if free_time - record.first_detected < @min_age
          next unless free_image(key, free_time, "space")

          deleted << key
          freed += record.size.to_i
          break if freed >= bytes_to_free
        end
        [deleted, freed]
      end

      def free_image(key, free_time, reason)
        return false unless @resolver.evict_cached_image(key, unused_since: free_time)

        @mutex.synchronize { @records.delete(key) }
        begin
          @on_collected&.call(reason)
        rescue StandardError
          nil
        end
        true
      rescue StandardError => error
        @error_handler&.call(error, :image_gc)
        false
      end

      def images_in_use
        Array(@pods.call).each_with_object(Set.new) do |pod, result|
          spec = pod.is_a?(Hash) ? (pod["spec"] || {}) : {}
          %w[initContainers containers ephemeralContainers].each do |field|
            Array(spec[field]).each do |container|
              image = container.is_a?(Hash) ? container["image"] : nil
              result << normalize_reference(image) if image
            end
          end
        end
      end

      def normalize_reference(image)
        Image::Reference.parse(image.to_s).to_s
      rescue StandardError
        image.to_s
      end

      def reference_of(key) = key.to_s.split("|").first.to_s

      def image_size(image)
        # A CRI runtime reports the size; the node's own store has a rootfs.
        return Integer(image.size_bytes) if image.respond_to?(:size_bytes) && image.size_bytes

        root = image.respond_to?(:rootfs) ? image.rootfs.to_s : ""
        root.empty? ? 0 : @size_of.call(root)
      rescue StandardError
        0
      end

      def directory_size(path)
        total = 0
        Find.find(path) do |entry|
          total += File.lstat(entry).blocks * 512
        rescue SystemCallError
          Find.prune
        end
        total
      end

      def event(type, reason, message)
        return unless @recorder && @node_ref

        @recorder.record(involved_object: @node_ref, reason: reason, type: type, message: message)
      rescue StandardError => error
        @error_handler&.call(error, :image_gc_event)
      end

      # formatSize.
      def format_size(bytes)
        kib = 1024.0
        size = bytes.to_f
        if size < kib then "#{bytes.to_i} B"
        elsif size < kib**2 then format("%.1f KiB", size / kib)
        elsif size < kib**3 then format("%.1f MiB", size / kib**2)
        elsif size < kib**4 then format("%.1f GiB", size / kib**3)
        else format("%.1f TiB", size / kib**4)
        end
      end
    end
  end
end
