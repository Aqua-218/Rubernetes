# frozen_string_literal: true

require "digest"
require "json"
require "time"
require_relative "source_manager"
require_relative "../pod_api_references"

module Rubernetes
  module Node
    # kubelet staticPodPath (pkg/kubelet/config/file.go, common.go) and its
    # mirror pods (pkg/kubelet/pod/mirror_client.go): the node runs the Pods
    # described by the manifests in a directory, re-read every
    # +interval+ seconds, without the API server; each gets a mirror Pod in
    # the API (annotation kubernetes.io/config.mirror, owned by the Node) so
    # it is visible there, and its status is written to the mirror.
    #
    # applyDefaults: the name gets "-<node name>", the namespace defaults to
    # "default", the UID is a digest of the node, the file and the Pod, which
    # is also kubernetes.io/config.hash, and the Pod tolerates every NoExecute
    # taint.  A Pod that references API objects (PreventStaticPodAPIReferences,
    # Beta, on) is refused, as an invalid one is.
    class StaticPods
      CONFIG_HASH = "kubernetes.io/config.hash"
      CONFIG_SOURCE = "kubernetes.io/config.source"
      CONFIG_SEEN = "kubernetes.io/config.seen"
      CONFIG_MIRROR = "kubernetes.io/config.mirror"
      DEFAULT_INTERVAL = 20

      attr_reader :errors
      attr_writer :lifecycle

      # +api+: #list(node_name:), #read_object, #create_mirror_pod,
      # #delete_pod.  +lifecycle+: #reconcile, #terminate.
      def initialize(path:, node_name:, lifecycle:, api: nil, interval: DEFAULT_INTERVAL, clock: -> { Time.now.utc },
                     sleeper: ->(seconds) { sleep(seconds) }, logger: nil)
        @path = File.expand_path(path)
        @node_name = node_name.to_s
        @lifecycle = lifecycle
        @api = api
        @interval = Float(interval)
        @clock = clock
        @sleeper = sleeper
        @logger = logger
        @parser = SourceManager.new(node_name: @node_name)
        @mutex = Mutex.new
        @pods = {}
        @mirrors = {}
        @errors = {}
        @thread = nil
        @running = false
      end

      def start
        @mutex.synchronize do
          return self if @running

          @running = true
        end
        @thread = Thread.new do
          while @mutex.synchronize { @running }
            sync
            @sleeper.call(@interval)
          end
        end
        self
      end

      def stop
        @mutex.synchronize { @running = false }
        @thread&.wakeup
        @thread&.join(5)
        @thread = nil
        self
      rescue ThreadError
        self
      end

      def pods = @mutex.synchronize { @pods.values }

      # The mirror Pod's UID for a static Pod (the status manager writes to it).
      def mirror_uid(static_uid) = @mutex.synchronize { @mirrors[static_uid.to_s] }

      def static?(pod)
        annotations = pod.dig("metadata", "annotations") || {}
        annotations[CONFIG_SOURCE] == "file" && annotations.key?(CONFIG_HASH)
      end

      # One pass: read the manifests, start/refresh/stop the Pods, keep the
      # mirrors in step.
      def sync
        desired = read_manifests
        previous = @mutex.synchronize { @pods.dup }
        (previous.keys - desired.keys).each do |uid|
          terminate(previous.fetch(uid))
        end
        desired.each_value do |pod|
          @lifecycle.reconcile(pod)
        rescue StandardError => error
          log(:warn, "static_pod.reconcile_failed", pod: pod.dig("metadata", "name"), error: error.message)
        end
        @mutex.synchronize { @pods = desired }
        sync_mirrors(desired)
        desired
      end

      # Upstream file source: every regular, non-hidden file is a manifest.
      def read_manifests
        errors = {}
        pods = {}
        return pods unless Dir.exist?(@path)

        Dir.children(@path).sort.each do |entry|
          next if entry.start_with?(".")

          file = File.join(@path, entry)
          next unless File.file?(file)

          begin
            documents = @parser.send(:invoke_parser, File.binread(file), file)
            list = if documents.is_a?(Hash)
                     documents["kind"] == "PodList" ? Array(documents["items"]) : [documents]
                   else
                     Array(documents)
                   end
            list.each do |document|
              next unless document.is_a?(Hash) && [nil, "Pod"].include?(document["kind"])

              pod = apply_defaults(document, file)
              resource = api_object_reference(pod)
              raise ArgumentError, "static pods may not reference #{resource}" if resource

              pods[pod.dig("metadata", "uid")] = pod
            end
          rescue StandardError => error
            errors[file] = error.message
            log(:warn, "static_pod.invalid", file: file, error: error.message)
          end
        end
        @errors = errors
        pods
      end

      # common.go applyDefaults.
      def apply_defaults(document, file)
        pod = JSON.parse(JSON.generate(document))
        pod["apiVersion"] ||= "v1"
        pod["kind"] = "Pod"
        metadata = (pod["metadata"] ||= {})
        spec = (pod["spec"] ||= {})
        if metadata["uid"].to_s.empty?
          digest = Digest::MD5.new
          digest << "host:#{@node_name}" << "file:#{file}" << JSON.generate(canonical(pod))
          metadata["uid"] = digest.hexdigest
        end
        metadata["name"] = "#{metadata["name"]}-#{@node_name.downcase}"
        metadata["namespace"] = "default" if metadata["namespace"].to_s.empty?
        spec["nodeName"] = @node_name
        annotations = (metadata["annotations"] ||= {})
        annotations[CONFIG_HASH] = metadata["uid"]
        annotations[CONFIG_SOURCE] = "file"
        annotations[CONFIG_SEEN] ||= @clock.call.utc.iso8601(9)
        # The node's NoExecute taints must not evict its own static Pods.
        tolerations = (spec["tolerations"] ||= [])
        tolerations << {"operator" => "Exists", "effect" => "NoExecute"}
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

        def report(pod, status)
          return @delegate.report(pod, status) unless @static_pods.static?(pod)

          mirror = @static_pods.mirror_uid(pod.dig("metadata", "uid"))
          return nil if mirror.nil?

          @delegate.report(pod.merge("metadata" => pod["metadata"].merge("uid" => mirror)), status)
        end

        def respond_to_missing?(name, include_private = false) = @delegate.respond_to?(name, include_private) || super

        def method_missing(name, ...)
          return super unless @delegate.respond_to?(name)

          @delegate.public_send(name, ...)
        end
      end

      private

      def terminate(pod)
        @lifecycle.terminate(pod)
      rescue StandardError => error
        log(:warn, "static_pod.terminate_failed", pod: pod.dig("metadata", "name"), error: error.message)
      end

      # mirror_client: create a mirror (the Node as controller owner) for
      # every static Pod that has none; replace one whose hash is stale;
      # delete mirrors whose static Pod is gone.
      def sync_mirrors(desired)
        return unless @api

        owner_uid = node_uid
        existing = Array(api_list).select { |pod| (pod.dig("metadata", "annotations") || {}).key?(CONFIG_MIRROR) }
        by_name = existing.to_h { |pod| ["#{pod.dig("metadata", "namespace")}/#{pod.dig("metadata", "name")}", pod] }
        mirrors = {}
        desired.each_value do |pod|
          key = "#{pod.dig("metadata", "namespace")}/#{pod.dig("metadata", "name")}"
          current = by_name.delete(key)
          hash = pod.dig("metadata", "annotations", CONFIG_HASH)
          if current && current.dig("metadata", "annotations", CONFIG_MIRROR) == hash && current.dig("metadata", "deletionTimestamp").nil?
            mirrors[pod.dig("metadata", "uid")] = current.dig("metadata", "uid")
            next
          end
          delete_mirror(current) if current && current.dig("metadata", "deletionTimestamp").nil?
          next if owner_uid.nil?

          created = create_mirror(pod, owner_uid)
          mirrors[pod.dig("metadata", "uid")] = created.dig("metadata", "uid") if created.is_a?(Hash)
        end
        by_name.each_value { |orphan| delete_mirror(orphan) }
        @mutex.synchronize { @mirrors = mirrors }
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
