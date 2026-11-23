# frozen_string_literal: true

require "digest"
require "json"
require "time"
require_relative "source_manager"
require_relative "static_pod_files"
require_relative "static_pod_http"
require_relative "../pod_api_references"

module Rubernetes
  module Node
    # kubelet staticPodPath and staticPodURL (pkg/kubelet/config): the node
    # runs Pods from both sources and publishes Node-owned mirrors and status.
    #
    # applyDefaults: the name gets "-<node name>", the namespace defaults to
    # "default", the UID is a digest of the node, the file and the Pod, which
    # is also kubernetes.io/config.hash.  File Pods tolerate every NoExecute
    # taint.  Invalid Pods and Pods with API object references are rejected.
    class StaticPods
      include StaticPodFiles

      CONFIG_HASH = "kubernetes.io/config.hash"
      CONFIG_SOURCE = "kubernetes.io/config.source"
      CONFIG_SEEN = "kubernetes.io/config.seen"
      CONFIG_MIRROR = "kubernetes.io/config.mirror"
      DEFAULT_INTERVAL = 20

      attr_writer :lifecycle, :pods_changed, :status_publisher, :enqueue_pod

      # +api+: #list(node_name:), #read_object, #create_mirror_pod,
      # #delete_pod.  +lifecycle+: #reconcile, #terminate.
      def initialize(node_name:, lifecycle:, path: nil, url: nil, url_headers: {}, http_interval: DEFAULT_INTERVAL,
                     api: nil, interval: DEFAULT_INTERVAL, clock: -> { Time.now.utc },
                     sleeper: ->(seconds) { sleep(seconds) }, logger: nil)
        @path = File.expand_path(path) if path
        unless url.to_s.empty?
          @url = url
          @http_source = StaticPodHTTP.new(url: url, headers: url_headers, max_bytes: SourceManager::MAX_MANIFEST_BYTES)
        end
        @node_name = node_name.to_s
        @lifecycle = lifecycle
        @api = api
        @interval = Float(interval)
        @http_interval = Float(http_interval)
        @clock = clock
        @sleeper = sleeper
        @logger = logger
        @parser = SourceManager.new(node_name: @node_name)
        @mutex = Mutex.new
        @sync_mutex = Mutex.new
        @source_pods = {file: {}, http: {}}
        @pods = {}
        @retiring = {}
        @file_origins = {}
        @file_restart_counts = {}
        @mirrors = {}
        @errors = {}
        @threads = []
        @poll_token = nil
      end

      def start
        @mutex.synchronize do
          return self if @poll_token

          token = @poll_token = Object.new
          @threads << start_file_watch(token) if @path
          @threads << poll(:http, @http_interval, token) { read_http_manifests } if @http_source
        end
        self
      end

      def stop
        threads = @mutex.synchronize do
          @poll_token = nil
          @file_stop_writer&.close
          @file_stop_writer = nil
          stopped = @threads
          @threads = []
          stopped
        end
        threads.each do |thread|
          thread.wakeup if thread.alive?
        rescue ThreadError
          next
        end
        threads.each { |thread| thread.join(StaticPodHTTP::TIMEOUT + 1) }
        self
      end

      def pods = @mutex.synchronize { @pods.values }
      def errors = @mutex.synchronize { @errors.dup }

      # The mirror Pod's UID for a static Pod (the status manager writes to it).
      def mirror_uid(static_uid) = @mutex.synchronize { @mirrors[static_uid.to_s] }

      def static?(pod)
        annotations = pod.dig("metadata", "annotations") || {}
        SourceManager::STATIC_SOURCES.include?(annotations[CONFIG_SOURCE]) && annotations.key?(CONFIG_HASH)
      end

      # One pass: read the manifests, start/refresh/stop the Pods, keep the
      # mirrors in step.
      def sync
        http = read_http_manifests if @http_source
        return refresh_files(http: http) if @path

        refresh_sources({http: http})
      end

      def refresh_sources(updates, token: nil)
        @sync_mutex.synchronize do
          return if token && !polling?(token)

          apply_sources(updates)
        end
      end

      def apply_sources(updates)
        @source_pods.merge!(updates.compact)
        file = @source_pods.fetch(:file)
        file_names = file.values.to_h { |pod| [full_name(pod), true] }
        http = @source_pods.fetch(:http).reject { |_uid, pod| file_names.key?(full_name(pod)) }
        reconcile_pods(http.merge(file))
      end

      def reconcile_pods(desired)
        previous = @mutex.synchronize { @pods.dup }
        (previous.keys - desired.keys).each do |uid|
          pod = previous.fetch(uid)
          @retiring[uid] = pod if @enqueue_pod
          terminate(pod)
        end
        @mutex.synchronize { @pods = desired }
        @pods_changed&.call
        retiring = retiring_pods_by_name
        runnable = desired.reject { |_uid, pod| retiring.key?(full_name(pod)) }
        sync_mirrors(runnable, retiring: retiring)
        runnable.each do |uid, pod|
          seed_file_restarts(uid)
          reconcile(pod)
        end
        desired
      end
      private :refresh_sources, :apply_sources, :reconcile_pods

      # A file is a complete source. A failed read keeps its last accepted
      # configuration, whereas removing the file withdraws its Pods.
      def read_manifests(origins: {})
        @mutex.synchronize { @errors.delete_if { |source, _error| source != :http } }
        stat = File.stat(@path)
        return read_file_pods(@path, origins: origins) if stat.file?
        raise ArgumentError, "static pod path must be a file or directory" unless stat.directory?

        Dir.children(@path).sort.each_with_object({}) do |entry, pods|
          next if entry.start_with?(".")

          file = File.join(@path, entry)
          next unless File.file?(file)

          begin
            pods.merge!(read_file_pods(file, origins: origins))
          rescue StandardError => error
            record_file_error(file, error)
          end
        end
      rescue Errno::ENOENT
        {}
      rescue StandardError => error
        record_file_error(@path, error)
        nil
      end

      def read_file_pods(file, origins:)
        documents = @parser.parse_file(file)
        list = if documents.is_a?(Hash)
                 documents["kind"] == "PodList" ? Array(documents["items"]) : [documents]
               else
                 Array(documents)
               end
        raise ArgumentError, "empty static Pod manifest" if list.empty?

        prepare_pods(list, file, source: "file").tap { |pods| origins[file] = pods.keys }
      end

      def prepare_pods(list, origin, source:)
        names = {}
        list.each_with_object({}) do |document, pods|
          raise ArgumentError, "expected a Pod in static Pod manifest" unless document.is_a?(Hash) && [nil, "Pod"].include?(document["kind"])
          raise ArgumentError, "static Pod requires metadata.name" if document.dig("metadata", "name").to_s.empty?

          pod = apply_defaults(document, origin, source: source)
          resource = api_object_reference(pod)
          raise ArgumentError, "static pods may not reference #{resource}" if resource

          if source == "http"
            validate_http_pod(pod)
            name = full_name(pod)
            next if names.key?(name)

            names[name] = true
          end
          pods[pod.dig("metadata", "uid")] = pod
        end
      end

      def record_file_error(file, error)
        @mutex.synchronize { @errors[file] = error.message }
        log(:warn, "static_pod.invalid", file: file, error: error.message)
      end
      private :read_file_pods, :prepare_pods, :record_file_error

      def read_http_manifests
        body = @http_source.read
        if body.empty?
          record_http_error("empty HTTP 200 response")
          return {}
        end
        if body == @last_http_body
          @mutex.synchronize { @errors.delete(:http) } if @last_http_valid
          return
        end

        @last_http_body = body
        @last_http_valid = false
        result = prepare_pods(http_documents(body), @url, source: "http")
        @last_http_valid = true
        @mutex.synchronize { @errors.delete(:http) }
        result
      rescue StaticPodHTTP::Error => error
        record_http_error(error.message)
        nil
      rescue StandardError => error
        record_http_error("invalid HTTP static Pod manifest (#{error.class})")
        nil
      end

      def http_documents(body)
        object = @parser.parse_content(body, "HTTP static Pod source")
        raise ArgumentError, "expected a v1 Pod or PodList" unless object.is_a?(Hash) && object["apiVersion"] == "v1"
        return [object] if object["kind"] == "Pod"
        raise ArgumentError, "expected a v1 Pod or PodList" unless object["kind"] == "PodList"

        items = object["items"] || []
        raise ArgumentError, "PodList items must be an array" unless items.is_a?(Array)

        items
      end

      def validate_http_pod(pod)
        require_relative "../../../generated/ruby/kubernetes_types"
        require_relative "../schema/kubernetes_validator"
        @http_definition ||= Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Pod")
        defaulted = @http_definition.defaulting.apply_hash(pod, kubernetes_admission_defaults: true)
        @http_definition.validator.validate!(defaulted, operation: :create)
        validate_http_containers(defaulted.fetch("spec"))
      end

      def validate_http_containers(spec)
        containers = %w[containers initContainers].flat_map { |key| Array(spec[key]) }
        if Array(spec["containers"]).empty? || containers.any? do |container|
          name = container["name"].to_s.b
          container["image"].to_s.empty? || !Schema::KubernetesValidator.dns1123_label_messages(name).empty?
        end
          raise ArgumentError, "static Pod requires valid container names and images"
        end
      end

      def record_http_error(message)
        log_change = @mutex.synchronize do
          next false if @errors[:http] == message

          @errors[:http] = message
        end
        log(:warn, "static_pod.http_failed", error: message) if log_change
      end
      private :read_http_manifests, :http_documents, :validate_http_pod, :validate_http_containers, :record_http_error

      # common.go applyDefaults.
      def apply_defaults(document, origin, source: "file")
        pod = JSON.parse(JSON.generate(document))
        pod["apiVersion"] ||= "v1"
        pod["kind"] = "Pod"
        metadata = (pod["metadata"] ||= {})
        spec = (pod["spec"] ||= {})
        if metadata["uid"].to_s.empty?
          digest = Digest::MD5.new
          identity = source == "file" ? "host:#{@node_name}file:#{origin}" : "url:#{origin}"
          digest << identity << JSON.generate(canonical(pod))
          metadata["uid"] = digest.hexdigest
        end
        metadata["name"] = "#{metadata["name"]}-#{@node_name.downcase}"
        metadata["namespace"] = "default" if metadata["namespace"].to_s.empty?
        spec["nodeName"] = @node_name
        annotations = (metadata["annotations"] ||= {})
        annotations[CONFIG_HASH] = metadata["uid"]
        annotations[CONFIG_SOURCE] = source
        annotations[CONFIG_SEEN] ||= @clock.call.utc.iso8601(9)
        # The node's NoExecute taints must not evict its own static Pods.
        if source == "file"
          tolerations = (spec["tolerations"] ||= [])
          tolerations << {"operator" => "Exists", "effect" => "NoExecute"}
        end
        pod["status"] = {"phase" => "Pending"}
        pod
      end

      # podutil.HasAPIObjectReference (PodAPIReferences).
      def api_object_reference(pod) = PodAPIReferences.find(pod)

      # A reporter wrapper: a static Pod's status goes to its mirror (by the
      # mirror's UID), and to nothing until the mirror exists.
      class Reporter
        def initialize(delegate, static_pods)
          @delegate = delegate
          @static_pods = static_pods
        end

        def status_report_target(pod)
          return pod if pod.dig("metadata", "annotations", CONFIG_MIRROR) || !@static_pods.static?(pod)

          mirror = @static_pods.mirror_uid(pod.dig("metadata", "uid"))
          return nil if mirror.nil?

          metadata = pod.fetch("metadata")
          annotations = metadata.fetch("annotations")
          mirror_annotations = annotations.merge(CONFIG_MIRROR => annotations.fetch(CONFIG_HASH))
          pod.merge("metadata" => metadata.merge("uid" => mirror, "annotations" => mirror_annotations))
        end

        def report(pod, status)
          target = status_report_target(pod)
          @delegate.report(target, status) if target
        end

        def respond_to_missing?(name, include_private = false) = @delegate.respond_to?(name, include_private) || super

        def method_missing(name, ...)
          return super unless @delegate.respond_to?(name)

          @delegate.public_send(name, ...)
        end
      end

      private

      def poll(source, interval, token)
        Thread.new do
          while polling?(token)
            snapshot = yield
            refresh_sources({source => snapshot}, token: token)
            @sleeper.call(interval) if polling?(token)
          end
        end
      end

      def polling?(token) = @mutex.synchronize { @poll_token.equal?(token) }

      def reconcile(pod)
        return @enqueue_pod.call(pod, action: "SYNC", worker_key: worker_key(pod)) if @enqueue_pod

        @lifecycle.reconcile(pod)
      rescue StandardError => error
        log(:warn, "static_pod.reconcile_failed", pod: pod.dig("metadata", "name"), error: error.message)
      end

      def terminate(pod)
        return @enqueue_pod.call(pod, action: "DELETED", worker_key: worker_key(pod)) if @enqueue_pod

        @lifecycle.terminate(pod)
      rescue StandardError => error
        log(:warn, "static_pod.terminate_failed", pod: pod.dig("metadata", "name"), error: error.message)
      end

      def full_name(pod) = "#{pod.dig("metadata", "namespace")}/#{pod.dig("metadata", "name")}"

      def worker_key(pod)
        "static:#{full_name(pod)}"
      end

      # Keep the old mirror during the grace period and keep a replacement
      # behind the previous UID until its runtime resources have been released.
      def retiring_pods_by_name
        @retiring.delete_if do |uid, pod|
          state = @lifecycle.record(uid)&.fetch(:state)
          terminate(pod) if state == "CleanupPending"
          state.nil?
        end
        @retiring.values.to_h { |pod| [full_name(pod), pod] }
      end

      # mirror_client: create a mirror (the Node as controller owner) for
      # every static Pod that has none; replace one whose hash is stale;
      # delete mirrors whose static Pod is gone.
      def sync_mirrors(desired, retiring:)
        return unless @api

        owner_uid = node_uid
        existing = Array(api_list).select { |pod| (pod.dig("metadata", "annotations") || {}).key?(CONFIG_MIRROR) }
        by_name = existing.to_h { |pod| [full_name(pod), pod] }
        mirrors = {}
        retiring.each do |name, pod|
          mirror = by_name.delete(name)
          uid = pod.dig("metadata", "uid")
          mirrors[uid] = mirror.dig("metadata", "uid") if mirror && mirror.dig("metadata", "annotations", CONFIG_MIRROR) == uid
        end
        desired.each_value do |pod|
          current = by_name.delete(full_name(pod))
          hash = pod.dig("metadata", "annotations", CONFIG_HASH)
          if current && current.dig("metadata", "annotations", CONFIG_MIRROR) == hash && current.dig("metadata", "deletionTimestamp").nil?
            mirrors[pod.dig("metadata", "uid")] = current.dig("metadata", "uid")
            next
          end
          # The mirror has no workload for the agent to stop. Clear the old
          # API object by UID even if an external graceful delete is pending.
          delete_mirror(current) if current
          next if owner_uid.nil?

          created = create_mirror(pod, owner_uid)
          mirrors[pod.dig("metadata", "uid")] = created.dig("metadata", "uid") if created.is_a?(Hash)
        end
        by_name.each_value { |orphan| delete_mirror(orphan) }
        @mutex.synchronize { @mirrors = mirrors }
        desired.each do |uid, pod|
          @status_publisher&.call(pod) if mirrors[uid]
        rescue StandardError => error
          log(:warn, "static_pod.mirror_status_failed", uid: uid, error: error.message)
        end
      rescue StandardError => error
        log(:warn, "static_pod.mirror_sync_failed", error: error.message)
      end

      def create_mirror(pod, node_uid)
        mirror = JSON.parse(JSON.generate(pod))
        metadata = mirror["metadata"]
        metadata.delete("uid")
        metadata["annotations"][CONFIG_MIRROR] = metadata["annotations"][CONFIG_HASH]
        metadata["ownerReferences"] =
          [{"apiVersion" => "v1", "kind" => "Node", "name" => @node_name, "uid" => node_uid, "controller" => true}]
        mirror.delete("status")
        @api.create_mirror_pod(mirror)
      rescue StandardError => error
        log(:warn, "static_pod.mirror_create_failed", pod: pod.dig("metadata", "name"), error: error.message)
        nil
      end

      def delete_mirror(mirror)
        @api.delete_pod(namespace: mirror.dig("metadata", "namespace"), name: mirror.dig("metadata", "name"),
                        uid: mirror.dig("metadata", "uid"))
      rescue StandardError => error
        log(:warn, "static_pod.mirror_delete_failed", pod: mirror.dig("metadata", "name"), error: error.message)
      end

      def api_list
        result = @api.list(node_name: @node_name)
        result.is_a?(Hash) ? Array(result["items"]) : Array(result)
      end

      def node_uid
        node = @api.read_object("nodes", @node_name)
        node.is_a?(Hash) ? node.dig("metadata", "uid") : nil
      rescue StandardError
        nil
      end

      def canonical(value)
        case value
        when Hash then value.keys.map(&:to_s).sort.to_h { |key| [key, canonical(value[key])] }
        when Array then value.map { |item| canonical(item) }
        else value
        end
      end

      def log(level, event, **fields)
        @logger&.public_send(level, event, **fields) if @logger.respond_to?(level)
      rescue StandardError
        nil
      end
    end
  end
end
