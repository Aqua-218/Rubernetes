# frozen_string_literal: true

require "json"
require "open3"
require "time"
require_relative "k6_project_pod_watch"
require_relative "../../lib/rubernetes/image"

module Conformance
  class K6ProjectImages
    Image = Rubernetes::Image
    PROJECT_STAGES = %w[install ready smoke scale upgrade rollback restart uninstall].freeze
    MAX_OBSERVATIONS = 4096
    CAPTURE_STAGES = %w[ready smoke restart].freeze
    STATUS_FIELDS = %w[containerStatuses initContainerStatuses ephemeralContainerStatuses].freeze

    def self.index_locks(locks)
      locks.to_h { |lock| [reference_key(lock), lock] }
    end

    def self.reference_key(value)
      reference = Image::Reference.parse(value)
      [reference.registry, reference.repository, reference.tag || reference.digest.to_s]
    rescue Image::ReferenceError
      value
    end

    def self.observed_digest(image_id)
      image_id.to_s[/sha256:[0-9a-f]{64}\z/]
    end

    def initialize(kubectl:, kubeconfig:, namespace:, locks:)
      command = [kubectl, "--kubeconfig", kubeconfig, "--namespace", namespace]
      @command = command + ["--request-timeout=20s"]
      @locks = self.class.index_locks(locks)
      @observations = {}
      @errors = []
      @manifest_digests = {}
      @lock = Mutex.new
      @stage_starts = {}
      @watch = K6ProjectPodWatch.new(command, namespace) { |pod, event, version| observe_watch(pod, event, version) }
    end

    def start_watch = @watch.start
    def stop_watch = @watch.stop

    def during(stage)
      @lock.synchronize do
        @current_stage = stage
        @stage_starts[stage] = Time.now.utc
      end
      yield
    end

    def capture(stage)
      out, _error, status = Open3.capture3(*@command, "get", "pods", "-o", "json", binmode: true)
      unless status.success?
        capture_error("#{stage}: namespace Pod LIST failed")
        return
      end

      JSON.parse(out.force_encoding(Encoding::UTF_8)).fetch("items").each do |pod|
        observe(pod, {"stage" => stage, "observation" => "list"})
      end
    rescue JSON::ParserError, KeyError, TypeError
      capture_error("#{stage}: namespace Pod LIST returned invalid JSON")
    end

    def result
      watch = @watch.evidence
      observations, errors = @lock.synchronize { [@observations.dup, @errors.dup] }
      images = observations.map do |(reference, id), source|
        lock = @locks[self.class.reference_key(reference)]
        record = image_source(source)
        record["watch_observation"] = image_source(source.fetch("watch_observation")) if source.key?("watch_observation")
        record.merge("reference" => reference, "image_id" => id, "lock" => lock, **verify(lock, id))
      end
      errors.concat(watch.fetch("errors"))
      errors << "no created containers were observed" if images.empty?
      {"passed" => watch.fetch("status") != "incomplete" && errors.empty? && images.all? { |image| image.fetch("passed") },
       "images" => images, "errors" => errors, "watch" => watch}
    end

    private

    def capture_error(message)
      @lock.synchronize { @errors << message }
    end

    def observe_watch(pod, event, version)
      stage = @lock.synchronize { @current_stage }
      observe(pod, {"stage" => stage || "install", "observation" => "watch", "watch_event" => event, "resource_version" => version})
    end

    def observe(pod, provenance)
      metadata = pod.fetch("metadata")
      STATUS_FIELDS.each do |field|
        Array(pod.dig("status", field)).each do |container|
          state = container.fetch("state", {})
          id = container["containerID"] || state.dig("terminated", "containerID")
          next if id.to_s.empty?

          key = [container["image"], container["imageID"]]
          source = provenance.merge("pod" => metadata.fetch("name"), "pod_uid" => metadata.fetch("uid"), "container" => container.fetch("name"))
          source["container_started_at"] = started_at(state) if provenance["observation"] == "watch"
          remember(key, source)
        end
      end
    end

    def started_at(state)
      state.dig("running", "startedAt") || state.dig("terminated", "startedAt")
    end

    def remember(key, source)
      @lock.synchronize do
        previous = @observations[key]
        if previous.nil? && @observations.size >= MAX_OBSERVATIONS
          error = "project image observations exceeded their limit"
          @errors << error unless @errors.include?(error)
        elsif previous.nil?
          @observations[key] = source
        elsif previous["observation"] == "watch" && source["observation"] == "list"
          @observations[key] = source.merge("watch_observation" => previous)
        elsif previous["observation"] == "list" && source["observation"] == "watch" && !previous.key?("watch_observation")
          @observations[key] = previous.merge("watch_observation" => source)
        end
      end
    end

    def image_source(source)
      record = source.except("container_started_at", "watch_observation")
      record["stage"] = watch_stage(source) if source["observation"] == "watch"
      record
    end

    # Watch frames can arrive after a stage finishes. Prefer the container's
    # start time when it clearly predates the stage open when read.
    def watch_stage(source)
      hint = source.fetch("stage")
      timestamp = source["container_started_at"]
      return hint unless timestamp

      starts = @lock.synchronize { @stage_starts.dup }
      time = Time.iso8601(timestamp)
      return hint if starts[hint] && time.to_i >= starts.fetch(hint).to_i

      starts.to_a.reverse_each.find { |_, started| time.to_i >= started.to_i }&.first || hint
    rescue ArgumentError
      hint
    end

    def verify(lock, id)
      return {"passed" => false, "reason" => "running image has no lock"} if lock.nil?

      observed = self.class.observed_digest(id)
      return {"passed" => false, "reason" => "container status has no manifest digest"} unless observed

      reference = Image::Reference.parse(lock)
      expected = reference.digest.to_s
      return {"passed" => true, "manifest_digest" => expected} if observed == expected

      expected = @manifest_digests[lock] ||= Image::RegistryClient.new(reference).manifest(reference).digest.to_s
      {"passed" => observed == expected, "manifest_digest" => expected}
    rescue Image::Error => error
      {"passed" => false, "reason" => "locked platform manifest: #{error.message}"}
    end
  end
end
