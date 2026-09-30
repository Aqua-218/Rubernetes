# frozen_string_literal: true

# Deterministic container and image garbage collection.  Selection is kept
# separate from deletion so policy can be tested with plain hashes and a
# runtime/image store can be injected only for the effectful reconciliation.

require "time"

require_relative "registration"

module Rubernetes
  module Node
    class GarbageCollector
      Report = Data.define(:containers, :images, :disk_usage, :dry_run) do
        def removed_containers
          containers
        end

        def removed_images
          images
        end

        def to_h
          {"containers" => containers, "images" => images, "diskUsage" => disk_usage, "dryRun" => dry_run}
        end
      end

      DEFAULT_CONTAINER_POLICY = {
        "min_age_seconds" => 0,
        "max_per_pod" => 1,
        "max_total" => nil
      }.freeze
      DEFAULT_IMAGE_POLICY = {
        "min_age_seconds" => 60,
        "high_threshold_percent" => 85.0,
        "low_threshold_percent" => 80.0,
        "max_images" => nil
      }.freeze

      def initialize(runtime: nil, image_store: nil, container_store: nil, event_recorder: nil,
                     container_policy: DEFAULT_CONTAINER_POLICY, image_policy: DEFAULT_IMAGE_POLICY,
                     container_gc_policy: nil, image_gc_policy: nil, clock: -> { Time.now.utc })
        @runtime = runtime
        @image_store = image_store
        @container_store = container_store
        @event_recorder = event_recorder
        @container_policy = normalize_policy(DEFAULT_CONTAINER_POLICY, container_gc_policy || container_policy)
        @image_policy = normalize_policy(DEFAULT_IMAGE_POLICY, image_gc_policy || image_policy)
        validate_policies!
        @clock = clock
        @mutex = Mutex.new
      end

      attr_reader :runtime, :image_store, :container_policy, :image_policy

      def collect(containers: nil, images: nil, disk_usage: nil, now: @clock.call, dry_run: true)
        timestamp = normalize_time(now)
        containers = source_items(containers, @container_store, :containers)
        images = source_items(images, @image_store, :images)
        usage = disk_usage || read_disk_usage
        running_images = referenced_images(containers)
        selected_containers = select_containers(containers, timestamp)
        selected_images = select_images(images, timestamp, usage, running_images)
        report = Report.new(containers: selected_containers.map { |item| Support.deep_copy(item) },
                            images: selected_images.map { |item| Support.deep_copy(item) },
                            disk_usage: Support.deep_copy(usage), dry_run: !!dry_run)
        return report if dry_run

        reconcile(report)
      end

      alias plan collect
      alias candidates collect

      def reconcile(report, dry_run: false)
        return report if dry_run

        removed_containers = []
        removed_images = []
        report.containers.each do |container|
          next unless remove_container(container)

          removed_containers << Support.deep_copy(container)
          record_event("ContainerGC", "removed terminated container #{container_id(container)}")
        end
        report.images.each do |image|
          next unless remove_image(image)

          removed_images << Support.deep_copy(image)
          record_event("ImageGC", "removed unused image #{image_id(image)}")
        end
        Report.new(containers: removed_containers, images: removed_images, disk_usage: report.disk_usage, dry_run: false)
      end

      def run(containers: nil, images: nil, disk_usage: nil, now: @clock.call)
        collect(containers: containers, images: images, disk_usage: disk_usage, now: now, dry_run: false)
      end

      alias collect! run
      alias garbage_collect run

      def select_containers(containers, now = @clock.call)
        timestamp = normalize_time(now)
        candidates = Array(containers).map { |item| Support.object_hash(item) }.select { |item| terminated?(item) }
        min_age = Float(@container_policy.fetch("min_age_seconds"))
        candidates.select! { |item| age_seconds(item, timestamp) >= min_age }
        grouped = candidates.group_by { |item| pod_key(item) }
        keep_per_pod = @container_policy["max_per_pod"]
        selected = if keep_per_pod.nil?
                     []
                   else
                     grouped.values.flat_map do |items|
                       items.sort_by { |item| timestamp_value(item) }.reverse.drop(Integer(keep_per_pod))
                     end
                   end
        max_total = @container_policy["max_total"]
        if max_total
          retained = candidates - selected
          overflow = retained.sort_by { |item| timestamp_value(item) }.first([retained.length - Integer(max_total), 0].max)
          selected.concat(overflow)
        end
        selected.sort_by { |item| [timestamp_value(item), container_id(item)] }
      end

      def select_images(images, now = @clock.call, disk_usage = nil, running_images = [])
        timestamp = normalize_time(now)
        candidates = Array(images).map { |item| Support.object_hash(item) }.select do |image|
          !image_in_use?(image, running_images) && age_seconds(image, timestamp) >= Float(@image_policy.fetch("min_age_seconds"))
        end
        max_images = @image_policy["max_images"]
        usage = normalize_disk_usage(disk_usage)
        over_high = usage && usage[:percent] >= Float(@image_policy.fetch("high_threshold_percent"))
        return [] unless over_high || (max_images && candidates.length > Integer(max_images))

        ordered = candidates.sort_by { |image| [timestamp_value(image), image_id(image)] }
        target_count = max_images && !over_high ? Integer(max_images) : nil
        selected = []
        current_bytes = usage && usage[:used_bytes]
        low_bytes = (usage[:capacity_bytes] * Float(@image_policy.fetch("low_threshold_percent")) / 100.0 if usage)
        ordered.each do |image|
          break if target_count && candidates.length - selected.length <= target_count
          break if over_high && current_bytes && current_bytes <= low_bytes

          selected << image
          current_bytes -= image_size(image) if current_bytes
        end
        selected
      end

      alias container_candidates select_containers
      alias image_candidates select_images

      private

      def normalize_policy(defaults, provided)
        Support.stringify_keys(defaults).merge(Support.stringify_keys(provided || {}))
      end

      def validate_policies!
        if @container_policy["max_per_pod"] && Integer(@container_policy["max_per_pod"]).negative?
          raise ArgumentError,
                "container max_per_pod must be non-negative"
        end

        high = Float(@image_policy.fetch("high_threshold_percent"))
        low = Float(@image_policy.fetch("low_threshold_percent"))
        raise ArgumentError, "image thresholds must be between 0 and 100" unless low >= 0 && high <= 100 && low <= high
      end

      def source_items(explicit, source, method_name)
        return explicit.is_a?(Hash) ? [explicit] : Array(explicit) unless explicit.nil?
        return [] unless source

        value = source.respond_to?(method_name) ? source.public_send(method_name) : []
        value.respond_to?(:items) ? value.items : Array(value)
      end

      def read_disk_usage
        return nil unless @image_store
        return @image_store.disk_usage if @image_store.respond_to?(:disk_usage)
        return @runtime.disk_usage if @runtime&.respond_to?(:disk_usage)

        nil
      end

      def referenced_images(containers)
        Array(containers).filter_map do |item|
          hash = Support.object_hash(item)
          next if terminated?(hash)

          Support.value(hash, "imageID") || Support.value(hash, "imageId") || Support.value(hash, "image") ||
            Support.value(hash, "digest")
        end.compact.to_set
      end

      def terminated?(container)
        state = Support.value(container, "state") || Support.value(container, "status")
        state = Support.value(state, "state", state) if state.is_a?(Hash)
        return true if %w[exited terminated stopped dead].include?(state.to_s.downcase)
        return true if Support.value(container, "running") == false
        return true if Support.value(container, "finishedAt") || Support.value(container, "finished_at")

        false
      end

      def pod_key(item)
        pod_uid = Support.value(item, "podUID") || Support.value(item, "podUid") || Support.value(item, "pod_uid")
        return "uid:#{pod_uid}" unless pod_uid.to_s.empty?

        namespace = Support.value(item, "podNamespace") || Support.value(item, "namespace") || "default"
        name = Support.value(item, "podName") || Support.value(item, "pod") || "unknown"
        "#{namespace}/#{name}"
      end

      def container_id(item)
        Support.value(item,
                      "id") || Support.value(item,
                                             "containerID") || Support.value(item,
                                                                             "containerId") || Support.value(item, "name") || "unknown"
      end

      def image_id(image)
        Support.value(image, "id") || Support.value(image, "digest") || Support.value(image, "imageID") ||
          Array(Support.value(image, "repoDigests", [])).first || image_name(image) || "unknown"
      end

      def image_name(image)
        Support.value(image, "name") || Support.value(image, "image")
      end

      def timestamp_value(item)
        value = Support.value(item, "finishedAt") || Support.value(item, "finished_at") ||
                Support.value(item, "lastUsed") || Support.value(item, "lastUsedAt") || Support.value(item, "createdAt") ||
                Support.value(item, "created_at")
        value ? normalize_time(value).to_f : 0.0
      rescue ArgumentError
        0.0
      end

      def age_seconds(item, now)
        [now.to_f - timestamp_value(item), 0].max
      end

      def image_size(image)
        Integer(Support.value(image, "sizeBytes", Support.value(image, "size", 0)) || 0)
      rescue ArgumentError, TypeError
        0
      end

      def image_in_use?(image, running_images)
        return true if Support.value(image, "inUse") == true || Support.value(image, "pinned") == true

        identity = image_id(image)
        name = image_name(image)
        running_images.include?(identity) || running_images.include?(name)
      end

      def normalize_disk_usage(value)
        return nil if value.nil?

        hash = Support.object_hash(value)
        used = Support.value(hash, "usedBytes") || Support.value(hash, "used_bytes") || Support.value(hash, "used")
        capacity = Support.value(hash, "capacityBytes") || Support.value(hash, "capacity_bytes") || Support.value(hash, "capacity")
        if used && capacity
          used = Integer(used)
          capacity = Integer(capacity)
          return nil if capacity <= 0

          return {used_bytes: used, capacity_bytes: capacity, percent: used.to_f / capacity * 100.0}
        end
        percent = Support.value(hash, "percent") || Support.value(hash, "usagePercent")
        if percent
          percent = percent.to_s.delete_suffix("%")
          return {used_bytes: nil, capacity_bytes: nil, percent: Float(percent)}
        end
        nil
      rescue ArgumentError, TypeError
        nil
      end

      def remove_container(container)
        return true unless @runtime || @container_store

        target = @runtime || @container_store
        id = container_id(container)
        method_name = %i[remove_container delete_container remove delete].find { |name| target.respond_to?(name) }
        return false unless method_name

        call_store(target, method_name, id, container)
      end

      def remove_image(image)
        return true unless @image_store

        method_name = %i[remove_image delete_image remove delete].find { |name| @image_store.respond_to?(name) }
        return false unless method_name

        call_store(@image_store, method_name, image_id(image), image)
      end

      def call_store(store, method_name, id, object)
        method = store.method(method_name)
        parameters = method.parameters
        keywords = {id: id, container_id: id, image_id: id, image: object, container: object, object: object}
        if parameters.any? { |kind, _| %i[key keyreq keyrest].include?(kind) }
          selected = if parameters.any? { |kind, _| kind == :keyrest }
                       keywords
                     else
                       names = parameters.filter_map { |kind, name| name if %i[key keyreq].include?(kind) }
                       keywords.select { |key, _| names.include?(key) }
                     end
          positional_count = parameters.any? { |kind, _| kind == :rest } ? 1 : parameters.count { |kind, _| %i[req opt].include?(kind) }
          result = method.call(*[id, object].first(positional_count), **selected)
        else
          positional_count = method.arity.negative? ? 1 : method.arity
          result = method.call(*[id, object].first(positional_count))
        end
        result != false
      end

      def record_event(reason, message)
        return unless @event_recorder
        if @event_recorder.respond_to?(:record)
          return @event_recorder.record(involved_object: {"kind" => "Node", "name" => "node"}, reason: reason,
                                        message: message)
        end

        @event_recorder.call(reason, message) if @event_recorder.respond_to?(:call)
      end

      def normalize_time(value)
        value.respond_to?(:utc) ? value.utc : Time.parse(value.to_s).utc
      end
    end

    NodeGarbageCollector = GarbageCollector unless const_defined?(:NodeGarbageCollector, false)
  end
end
