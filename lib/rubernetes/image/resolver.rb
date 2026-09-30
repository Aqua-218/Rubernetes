# frozen_string_literal: true

require "fileutils"
require "json"
require "tmpdir"

require_relative "manifest"
require_relative "puller"
require_relative "pull_records"
require_relative "reference"
require_relative "registry_client"
require_relative "strict_json"
require_relative "../platform/linux/secure_rootfs"

module Rubernetes
  module Image
    # Resolves a Kubernetes image reference into an immutable, executable
    # image description. Resolution is deliberately a separate port from the
    # runtime so a node can verify every image before it allocates a sandbox.
    class Resolver
      ResolvedImage = Data.define(
        :reference, :digest, :manifest, :rootfs, :stage_token, :config,
        :entrypoint, :cmd, :env, :working_dir, :os, :architecture
      ) do
        def command
          (Array(entrypoint) + Array(cmd)).freeze
        end

        def to_h
          {
            "reference" => reference.to_s,
            "digest" => digest.to_s,
            "manifest" => manifest_document,
            "manifest_raw" => manifest_raw_bytes,
            "rootfs" => rootfs,
            "config" => config,
            "entrypoint" => entrypoint,
            "cmd" => cmd,
            "env" => env,
            "working_dir" => working_dir,
            "os" => os,
            "architecture" => architecture
          }
        end

        private

        # The token is intentionally not part of the public image document.
        # Resolver#release validates object identity against its private
        # registry before any staging path can be removed.
        private :stage_token

        # The raw manifest bytes are what the pinned digest covers; the
        # runtime's verifier re-hashes them rather than trusting the digest.
        def manifest_raw_bytes
          return manifest.raw.dup.force_encoding(Encoding::UTF_8) if manifest.respond_to?(:raw) && manifest.raw

          nil
        end

        def manifest_document
          return manifest.to_h if manifest.respond_to?(:to_h)
          return StrictJSON.parse(manifest.raw, max_bytes: 8 * 1024 * 1024) if manifest.respond_to?(:raw) && manifest.raw

          nil
        end
      end

      # +pull_records+: KubeletEnsureSecretPulledImages (on by default, with
      # the NeverVerifyPreloadedImages policy); nil turns the check off.
      def initialize(puller: nil, puller_factory: nil, platform: nil, staging_root: nil, pull_records: PullRecords.new)
        if puller && puller_factory
          raise ArgumentError, "puller and puller_factory are mutually exclusive"
        end

        @puller = puller
        @puller_factory = puller_factory || lambda do |reference, credentials = nil|
          options = {}
          if credentials
            value = credentials.respond_to?(:to_h) ? credentials.to_h : credentials
            options[:username] = value[:username] || value["username"] if value[:username] || value["username"]
            options[:password] = value[:password] || value["password"] if value[:password] || value["password"]
          end
          Puller.new(registry_client: RegistryClient.new(reference, **options))
        end
        @platform = Platform.coerce(platform || Platform.current)
        @staging_root = staging_root && File.expand_path(String(staging_root))
        if @staging_root
          FileUtils.mkdir_p(@staging_root, mode: 0o700)
          staging_stat = File.lstat(@staging_root)
          raise StoreError, "image staging root must be a real directory" unless staging_stat.directory? && !staging_stat.symlink?
        end
        @stage_registry = {}
        @stage_registry_mutex = Mutex.new
        # Resolved-image cache.  Without it every Pod re-pulled AND re-unpacked
        # its image into a fresh rootfs: measured at 83s per Pod for
        # agnhost:2.57 on a node that had already unpacked it minutes earlier.
        # That is ~85s added to every Pod in every conformance spec -- the
        # dominant cause both of specs timing out and of a 446-spec run taking
        # 40h instead of 3h.  Upstream never re-pulls for the default
        # imagePullPolicy of a tagged image (IfNotPresent).
        #
        # The unpacked rootfs is only ever used as a read-only overlay
        # lowerdir, so sharing one between containers is what upstream does
        # too; each container still gets its own workspace (upper).
        @image_cache = {}
        # Monotonic time each cached image was last handed out: the image
        # garbage collector's lastUsed, and what keeps an image that a Pod is
        # starting from right now out of its reach.
        @image_last_used = {}
        @image_cache_mutex = Mutex.new
        # Pulls in progress, by cache key: Pods started together on a node
        # (a DaemonSet, a ReplicaSet's first batch, a DNS spec's queriers)
        # all asked for the same image before any pull finished, and each ran
        # its own download and unpack of it.
        @inflight = {}
        @pull_records = pull_records
      end

      attr_reader :platform, :staging_root, :pull_records

      # Dir.mktmpdir embeds the creating pid, which is the only durable link
      # between a staging directory and its owner.
      STAGE_NAME = /\Arubernetes-image-\d{8}-(\d+)-[A-Za-z0-9_]+\z/

      # An agent that dies with pods running leaves its staging directories
      # behind, and its state directory -- the only record of them -- goes with
      # the cluster.  Nothing then refers to gigabytes of extracted rootfs, so
      # a node that restarts often fills its disk and every later image pull
      # fails with ENOSPC.  Reclaim on startup: a directory whose creating pid
      # is gone can no longer be released by anyone.  A pid that still exists
      # is left alone, so a reused pid only ever costs a missed reclaim.
      def self.reclaim_abandoned_stages(staging_root: nil, logger: nil)
        parent = staging_root ? File.expand_path(String(staging_root)) : Dir.tmpdir
        reclaimed = 0
        Dir.children(parent).each do |name|
          match = STAGE_NAME.match(name)
          next unless match
          next if Integer(match[1]) == Process.pid || process_alive?(Integer(match[1]))

          stat = File.lstat(File.join(parent, name))
          next unless stat.directory? && !stat.symlink?

          filesystem = ::Rubernetes::Platform::Linux::SecureRootfs.new(root: parent)
          filesystem.remove(name, expected_identity: [stat.dev, stat.ino, stat.mode])
          reclaimed += 1
        rescue SystemCallError, StoreError, ::Rubernetes::Platform::Linux::SecureRootfs::Error
          next
        end
        logger&.call(:info, "image.stages_reclaimed", count: reclaimed) if reclaimed.positive?
        reclaimed
      rescue SystemCallError
        0
      end

      def self.process_alive?(pid)
        Process.kill(0, pid)
        true
      rescue Errno::ESRCH
        false
      rescue Errno::EPERM
        true
      end

      # Pulls and verifies one image. A tag is resolved exactly once by the
      # Puller and the returned reference is always digest-pinned.
      #
      # +pull_secret+ names the Secret +credentials+ came from ({uid:,
      # namespace:, name:, hash:}; nil for an anonymous or node-wide pull) and
      # +pod_credentials+ answers every Secret of the Pod for this image
      # (-> [[pull_secret...], service_account]).  With pull records, an image
      # served from the cache -- a cache hit, or another Pod's pull joined in
      # flight -- must be one those credentials could pull
      # (KubeletEnsureSecretPulledImages); an anonymous image or a matching
      # Secret costs a hash lookup, anything else a manifest request with the
      # Pod's own credentials.
      #
      # +on_pull+ hears about every pull kubelet's image manager would make
      # (pullImage: a cache miss, pull policy Always, or an image the Pod has
      # to prove it may use): (:start), then (:done, seconds, size_bytes) or
      # (:failed, error).  An image used as it is makes no call.  First it
      # hears (:present, bool), whether the image was on the node already,
      # and (:required) when policy Never refuses an image the Pod may not
      # use as it is.
      def resolve(reference, platform: nil, rootfs: nil, credentials: nil, pull_policy: nil, pull_secret: nil, pod_credentials: nil,
                  on_pull: nil, **_context)
        image_reference = Reference.parse(reference)
        target = Platform.coerce(platform || @platform)
        owned_stage = rootfs.nil?
        # A caller-supplied rootfs owns its own destination, and "Always" asks
        # for a fresh pull; everything else may reuse an already unpacked
        # image, which is the IfNotPresent/Never behaviour.
        cache_key = cacheable_key(image_reference, target, owned_stage, pull_policy)
        policy = pull_policy.to_s
        if cache_key
          cached = cached_image(cache_key)
          on_pull&.call(:present, !cached.nil?)
          # imagePullPolicy Never: only an image already here, never a pull.
          if policy.casecmp("Never").zero?
            raise NeverPullError, "Container image #{reference.to_s.inspect} is not present with pull policy of Never" unless cached
            if @pull_records && @pull_records.must_attempt_pull?(repository_key(image_reference), cached.digest.to_s,
                                                                 pod_credentials || default_pod_credentials(pull_secret))
              on_pull&.call(:required)
              raise NeverPullError, "Container image #{reference.to_s.inspect} is not present with pull policy of Never"
            end

            return cached
          end
          # imagePullPolicy Always: the registry is asked every time, with the
          # Pod's credentials; an unchanged digest reuses the unpacked image.
          if cached && policy.casecmp("Always").zero?
            return pulling(on_pull) { always_pull(cached, image_reference, target, credentials, pull_secret) }
          end
          return accessible(cached, image_reference, target, credentials, pull_secret, pod_credentials, on_pull) if cached

          image = pulling(on_pull) do
            join_or_lead(cache_key) do
              pull_and_resolve(image_reference, target, owned_stage, rootfs, credentials, cache_key, pull_secret)
            end
          end
          return accessible(image, image_reference, target, credentials, pull_secret, pod_credentials, nil)
        end
        on_pull&.call(:present, false)
        pulling(on_pull) { pull_and_resolve(image_reference, target, owned_stage, rootfs, credentials, nil, pull_secret) }
      end

      def pulling(on_pull)
        return yield if on_pull.nil?

        on_pull.call(:start)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        image = yield
        on_pull.call(:done, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, image_size(image))
        image
      rescue StandardError => error
        on_pull&.call(:failed, error)
        raise
      end
      private :pulling

      # The image's size as the runtime reports it: its config and layer
      # blobs.
      def image_size(image)
        manifest = image.respond_to?(:manifest) ? image.manifest : nil
        return 0 unless manifest.is_a?(Hash)

        blobs = Array(manifest["layers"]) + [manifest["config"]].compact
        blobs.sum { |blob| blob.is_a?(Hash) ? blob["size"].to_i : 0 }
      rescue StandardError
        0
      end
      private :image_size

      # One pull per cache key at a time: the first caller pulls, the others
      # wait for it and share its result (or retry themselves if it failed,
      # since a pull can fail for a reason that is theirs alone -- a
      # credential, a deadline).
      def join_or_lead(cache_key)
        flight, leader = @image_cache_mutex.synchronize do
          existing = @inflight[cache_key]
          next [existing, false] if existing

          @inflight[cache_key] = {mutex: Mutex.new, condition: ConditionVariable.new, done: false}
          [@inflight[cache_key], true]
        end
        unless leader
          flight[:mutex].synchronize { flight[:condition].wait(flight[:mutex]) until flight[:done] }
          cached = cached_image(cache_key)
          return cached if cached

          return yield
        end
        begin
          yield
        ensure
          @image_cache_mutex.synchronize { @inflight.delete(cache_key) }
          flight[:mutex].synchronize do
            flight[:done] = true
            flight[:condition].broadcast
          end
        end
      end
      private :join_or_lead

      def pull_and_resolve(image_reference, target, owned_stage, rootfs, credentials, cache_key, pull_secret = nil)
        @pull_records&.record_intent(image_reference.to_s)
        destination, stage_token = owned_stage ? allocate_staging_root : [File.expand_path(String(rootfs)), nil]
        puller = @puller || build_puller(image_reference, credentials)
        image = puller.pull(image_reference, platform: target, rootfs: destination, unpack: true)
        config = normalize_config(image)
        image_platform = validate_platform!(config, target)
        runtime_config = config.fetch("config", {})
        unless runtime_config.is_a?(Hash)
          raise ManifestError, "image config field must be a JSON object"
        end

        resolved = ResolvedImage.new(
          reference: Reference.parse(image.reference),
          digest: Digest.parse(image.digest),
          manifest: image.manifest,
          rootfs: File.expand_path(String(image.rootfs || destination)),
          stage_token: stage_token,
          config: immutable(config),
          entrypoint: normalize_argv(runtime_config["Entrypoint"], "image Entrypoint"),
          cmd: normalize_argv(runtime_config["Cmd"], "image Cmd"),
          env: normalize_env(runtime_config["Env"]),
          working_dir: normalize_working_dir(runtime_config["WorkingDir"]),
          os: image_platform.os,
          architecture: image_platform.architecture
        ).freeze
        raise ManifestError, "image config has no Entrypoint or Cmd" if resolved.command.empty?

        store_image(cache_key, resolved) if cache_key
        record_pull(image_reference, resolved.digest, pull_secret)
        resolved
      rescue StandardError
        release_stage(stage_token) if defined?(stage_token) && stage_token
        raise
      end

      # MustAttemptImagePull for an image this resolver already has: the
      # image as is when the Pod may use it, else proof with the Pod's own
      # credentials -- the manifest digest when the puller can fetch just
      # that (the unpacked image is reused), otherwise a pull of its own.
      def accessible(image, image_reference, target, credentials, pull_secret, pod_credentials, on_pull = nil)
        return image unless @pull_records

        repository = repository_key(image_reference)
        pod_credentials ||= default_pod_credentials(pull_secret)
        return image unless @pull_records.must_attempt_pull?(repository, image.digest.to_s, pod_credentials)
        return pulling(on_pull) { prove_access(image, image_reference, target, credentials, pull_secret) } if on_pull

        prove_access(image, image_reference, target, credentials, pull_secret)
      end
      private :accessible

      def prove_access(image, image_reference, target, credentials, pull_secret)
        puller = @puller || build_puller(image_reference, credentials)
        if puller.respond_to?(:resolve_digest)
          digest = puller.resolve_digest(image_reference, platform: target)
          if digest.to_s == image.digest.to_s
            record_pull(image_reference, image.digest, pull_secret)
            return image
          end
        end
        pull_and_resolve(image_reference, target, true, nil, credentials, nil, pull_secret)
      end
      private :prove_access

      def always_pull(cached, image_reference, target, credentials, pull_secret)
        puller = @puller || build_puller(image_reference, credentials)
        if puller.respond_to?(:resolve_digest) && puller.resolve_digest(image_reference, platform: target).to_s == cached.digest.to_s
          record_pull(image_reference, cached.digest, pull_secret)
          return cached
        end
        # A new digest (or no way to ask for just the digest): a pull of its
        # own, released with the Pod; the cached image stays for its users.
        pull_and_resolve(image_reference, target, true, nil, credentials, nil, pull_secret)
      end
      private :always_pull

      # The pull's own credential, when the caller gave no Pod credentials.
      def default_pod_credentials(pull_secret)
        lambda do
          next [[], nil] if pull_secret.nil?
          next [[], pull_secret[:service_account]] if pull_secret[:service_account]

          [[pull_secret], nil]
        end
      end
      private :default_pod_credentials

      def record_pull(image_reference, digest, pull_secret)
        return unless @pull_records

        credentials = if pull_secret.nil?
                        PullRecords::Credentials.node
                      elsif pull_secret[:service_account]
                        PullRecords::Credentials.new(node_accessible: false, secrets: [], service_accounts: [pull_secret[:service_account]])
                      else
                        PullRecords::Credentials.secret(**pull_secret.slice(:uid, :namespace, :name, :hash))
                      end
        @pull_records.record_pulled(repository_key(image_reference), digest.to_s, credentials)
        @pull_records.clear_intent(image_reference.to_s)
      end
      private :record_pull

      # The image name without tag or digest, the pull records' key.
      def repository_key(image_reference) = "#{image_reference.registry}/#{image_reference.repository}"
      private :repository_key

      # A pull's registry credentials (imagePullSecrets) go to the puller
      # factory when it takes them; a one-argument factory keeps working.
      def build_puller(image_reference, credentials)
        arity = @puller_factory.respond_to?(:arity) ? @puller_factory.arity : @puller_factory.method(:call).arity
        return @puller_factory.call(image_reference, credentials) if credentials && (arity >= 2 || arity < -1 || arity == -1)

        @puller_factory.call(image_reference)
      rescue ArgumentError => error
        raise unless error.message.include?("wrong number of arguments")

        @puller_factory.call(image_reference)
      end

      # Releases only directories allocated by this resolver. Caller-owned
      # rootfs paths are never removed by the image subsystem.
      #
      # A cached image is shared: every Pod resolving the same reference gets
      # the same unpacked rootfs as its overlay lowerdir.  Releasing it when
      # one of those Pods is torn down deleted the image under every other Pod
      # still running from it -- "exec: cat: executable file not found" in a
      # running container, "rootfs path must be a regular directory" for the
      # next Pod.  A cached stage stays until the cache itself lets it go.
      def release(image)
        token = image.respond_to?(:stage_token, true) ? image.__send__(:stage_token) : nil
        return true if token.nil?
        return true if cached_stage?(token)

        release_stage(token)
      end

      # Image garbage collection (node/image_gc_manager.rb): the cached,
      # unpacked images as [key, image, last used (monotonic seconds)].
      def cached_images
        @image_cache_mutex.synchronize do
          @image_cache.map { |key, entry| [key, entry, @image_last_used[key]] }
        end
      end

      # Drop a cached image and delete its unpacked rootfs -- unless it was
      # handed out after +unused_since+ (monotonic), which means a Pod is
      # starting from it and the collector's view is stale.
      def evict_cached_image(key, unused_since: nil)
        entry = @image_cache_mutex.synchronize do
          last = @image_last_used[key]
          next nil if unused_since && last && last > unused_since

          @image_last_used.delete(key)
          @image_cache.delete(key).tap do |removed|
            # PruneUnknownRecords: the image is gone from the node.
            if removed.respond_to?(:digest) && @pull_records &&
               @image_cache.each_value.none? { |other| other.respond_to?(:digest) && other.digest.to_s == removed.digest.to_s }
              @pull_records.forget(removed.digest.to_s)
            end
          end
        end
        return false unless entry

        token = entry.__send__(:stage_token)
        token ? release_stage(token) : true
      end

      private

      def image_clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      # Only an image we unpacked into a stage we own can be handed to the next
      # caller: the rootfs has to outlive this resolve, which a caller-supplied
      # destination does not guarantee.
      def cacheable_key(image_reference, target, owned_stage, _pull_policy)
        return nil unless owned_stage

        [image_reference.to_s, target.os.to_s, target.architecture.to_s].join("|")
      end

      # A cached entry is only good while its unpacked rootfs is still there;
      # an out-of-band reclaim must not turn into a container that cannot start.
      def cached_image(key)
        entry = @image_cache_mutex.synchronize { @image_cache[key] }
        return nil unless entry

        root = entry.rootfs.to_s
        if !root.empty? && File.directory?(root)
          @image_cache_mutex.synchronize { @image_last_used[key] = image_clock }
          return entry
        end

        @image_cache_mutex.synchronize do
          @image_cache.delete(key)
          @image_last_used.delete(key)
        end
        nil
      end

      def cached_stage?(token)
        @image_cache_mutex.synchronize do
          @image_cache.each_value.any? { |entry| entry.__send__(:stage_token).equal?(token) }
        end
      end

      def store_image(key, resolved)
        @image_cache_mutex.synchronize do
          @image_last_used[key] = image_clock
          @image_cache[key] ||= resolved
        end
      end

      def allocate_staging_root
        parent = @staging_root || Dir.tmpdir
        stage = Dir.mktmpdir("rubernetes-image-", parent)
        token = Object.new.freeze
        stat = File.lstat(stage)
        entry = {
          token: token,
          parent: File.dirname(stage).freeze,
          basename: File.basename(stage).freeze,
          identity: [stat.dev, stat.ino, stat.mode].freeze
        }.freeze
        @stage_registry_mutex.synchronize { @stage_registry[token.__id__] = entry }
        [File.join(stage, "rootfs"), token]
      rescue SystemCallError => error
        # The lease is not registered until its descriptor identity is known;
        # leave an uncertain allocation for an out-of-band janitor instead of
        # deleting a pathname that may have been replaced during setup.
        raise StoreError.new("cannot allocate image staging root: #{error.message}", cause: error), cause: error
      end

      def normalize_config(image)
        value = image.respond_to?(:config_object) ? image.config_object : nil
        value ||= StrictJSON.parse(String(image.config), max_bytes: Puller::DEFAULT_MAX_CONFIG_BYTES)
        raise ManifestError, "image config must be a JSON object" unless value.is_a?(Hash)

        value
      rescue StrictJSON::Error, JSON::ParserError => error
        raise ManifestError.new("image config is not valid JSON: #{error.message}", cause: error), cause: error
      end

      def validate_platform!(config, target)
        image_os = config["os"]
        image_architecture = config["architecture"]
        if image_os && image_os.to_s != target.os
          raise ManifestError, "image config OS #{image_os.inspect} does not match #{target.os.inspect}"
        end
        if image_architecture && Platform::ARCHITECTURES.fetch(image_architecture.to_s, image_architecture.to_s) != target.architecture
          raise ManifestError, "image config architecture #{image_architecture.inspect} does not match #{target.architecture.inspect}"
        end
        target
      end

      def normalize_argv(value, label)
        return [].freeze if value.nil?
        raise ManifestError, "#{label} must be an array" unless value.is_a?(Array)

        value.map do |argument|
          text = String(argument)
          raise ManifestError, "#{label} contains NUL" if text.include?("\0")

          text.freeze
        end.freeze
      rescue TypeError => error
        raise ManifestError.new("#{label} contains a non-string value: #{error.message}", cause: error), cause: error
      end

      def normalize_env(value)
        return {}.freeze if value.nil?
        raise ManifestError, "image Env must be an array" unless value.is_a?(Array)

        value.each_with_object({}) do |entry, result|
          text = String(entry)
          name, separator, content = text.partition("=")
          raise ManifestError, "image Env entry must contain a variable name" if separator.empty? || !name.match?(/\A[A-Za-z_][A-Za-z0-9_]*\z/)
          raise ManifestError, "image Env contains NUL" if text.include?("\0")

          result[name] = content
        end.freeze
      rescue TypeError => error
        raise ManifestError.new("image Env contains a non-string value: #{error.message}", cause: error), cause: error
      end

      def normalize_working_dir(value)
        return nil if value.nil? || value.to_s.empty?
        text = String(value)
        raise ManifestError, "image WorkingDir must be absolute" unless text.start_with?("/")
        raise ManifestError, "image WorkingDir contains NUL" if text.include?("\0")

        text.freeze
      end

      def immutable(value)
        case value
        when Hash then value.to_h { |key, child| [String(key).freeze, immutable(child)] }.freeze
        when Array then value.map { |child| immutable(child) }.freeze
        else value.freeze
        end
      end

      def release_stage(token)
        entry = @stage_registry_mutex.synchronize do
          candidate = @stage_registry[token.__id__]
          candidate if candidate && candidate.fetch(:token).equal?(token)
        end
        return false unless entry

        begin
          secure_remove_stage(entry)
        rescue StoreError, SystemCallError, ::Rubernetes::Platform::Linux::SecureRootfs::Error
          # Keep the registry entry for a later ownership-ledger retry. A
          # failed identity check or unavailable secure backend must never turn
          # into a best-effort deletion of an arbitrary pathname.
          return false
        end
        @stage_registry_mutex.synchronize { @stage_registry.delete(token.__id__) }
        true
      end

      def secure_remove_stage(entry)
        filesystem = ::Rubernetes::Platform::Linux::SecureRootfs.new(root: entry.fetch(:parent))
        begin
          current = filesystem.identity(entry.fetch(:basename))
          raise StoreError, "image staging identity changed" unless current == entry.fetch(:identity)

          filesystem.remove(entry.fetch(:basename), expected_identity: entry.fetch(:identity))
        ensure
          filesystem.close
        end
      end
    end
  end
end
