# frozen_string_literal: true

require "cgi"
require "time"

module Rubernetes
  module Node
    module PodLogsEndpoint
      private

      # kubelet/apiserver behaviour for a container that exists but has not
      # started: a 400 whose message names the state.  Clients (hydrophone
      # included) branch on this instead of on a generic 5xx.
      NOT_STARTED = /unknown container|not running|no such container/i

      # kubelet waits for a container that is still being created when the
      # request is a follow; only a non-follow request is answered with the
      # "waiting to start" 400.  Clients stream a pod's logs the moment it is
      # scheduled and rely on that wait.
      FOLLOW_START_TIMEOUT = Float(ENV.fetch("RUBERNETES_LOG_FOLLOW_TIMEOUT", "300"))
      FOLLOW_POLL_INTERVAL = 0.5
      SHORT_START_TIMEOUT = Float(ENV.fetch("RUBERNETES_LOG_START_TIMEOUT", "30"))

      # Both PodLogOptions forms name a moment, never a byte offset.
      def log_since(request)
        seconds = request.query_value("sinceSeconds").to_s
        return (Time.now.utc - Integer(seconds)).iso8601(9) unless seconds.empty?

        time = request.query_value("sinceTime").to_s
        time.empty? ? nil : Time.iso8601(time).utc.iso8601(9)
      end

      def container_logs(match, request)
        follow = query_bool(request, "follow")
        stream = request.query_value("stream", "All")
        tail = request.query_value("tailLines")
        legacy_tail = request.query_value("tail").to_s
        tail = (legacy_tail == "all" ? nil : legacy_tail) unless legacy_tail.empty?
        return [422, {"content-type" => "text/plain"}, ["Invalid request.\n"]] unless %w[All Stdout Stderr].include?(stream) && (stream == "All" || tail.nil?)

        if !@split_log_streams && stream != "All"
          return [400, {"content-type" => "text/plain"},
                  ["unable to return the given log stream: #{stream.inspect}. Please enable PodLogsQuerySplitStreams feature gate in kubelet\n"]]
        end
        namespace, pod, name = %i[namespace pod container].map { |key| CGI.unescape(match[key]) }
        previous = query_bool(request, "previous")
        if previous
          container, sandbox_id, archived_log_path = previous_log_target(namespace, pod, name)
          return [400, {"content-type" => "text/plain"}, ["previous terminated container #{name.inspect} in pod #{pod.inspect} not found\n"]] if container.nil?
        else
          container = await_container(namespace, pod, name, follow: follow)
        end
        result = @log_service.logs(
          container,
          follow: follow && !previous,
          sandbox_id: sandbox_id,
          archived_log_path: archived_log_path,
          since: log_since(request),
          tail: tail,
          stream: stream.downcase.to_sym,
          timestamps: query_bool(request, "timestamps"),
          limit_bytes: request.query_value("limitBytes"),
          request_id: request.query_value("requestID"),
          identity: "node-streaming"
        )
        {status: 200, headers: {"content-type" => "text/plain; charset=utf-8"}, body: body_for(result), stream: true}
      rescue StandardError => error
        raise unless NOT_STARTED.match?(error.message)

        pod = CGI.unescape(match[:pod])
        namespace = CGI.unescape(match[:namespace])
        container = CGI.unescape(match[:container])
        [400, {"content-type" => "text/plain"},
         ["container #{container.inspect} in pod #{pod.inspect} is waiting to start: ContainerCreating " \
          "(namespace #{namespace})\n"]]
      end

      def previous_log_target(namespace, pod, name)
        record = pod_record(namespace, pod)
        entry = record_containers(record).find { |candidate| (candidate[:name] || candidate["name"]).to_s == name }
        state = entry && (entry[:status] || entry["status"] || {})
        id = state&.dig("lastState", "terminated", "containerID").to_s
        return if id.empty?

        previous_id = entry[:previous_id] || entry["previous_id"]
        archived_log_path = entry[:previous_log_path] || entry["previous_log_path"] if previous_id == id
        [id, record[:sandbox_id] || record["sandbox_id"], archived_log_path]
      end
    end
  end
end
