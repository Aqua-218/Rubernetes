# frozen_string_literal: true

require "base64"
require "digest"
require "fileutils"
require "json"
require "monitor"
require "securerandom"

module Rubernetes
  module Volume
    # Atomic writer compatible with Kubernetes projected volumes.  A complete
    # generation is fsync'd before the ..data symlink is swapped, so readers
    # observe either the old generation or the new one and never a partial set.
    class AtomicWriter
      DATA_LINK = "..data"
      GENERATION_PREFIX = ".."

      def initialize(root, fsync: true, clock: -> { Time.now.utc }, tmpfs: false, mount_adapter: nil)
        @root = File.expand_path(String(root))
        @fsync = fsync
        @clock = clock
        @tmpfs = tmpfs == true
        @mount_adapter = mount_adapter
        @mutex = Monitor.new
        raise PathSecurityError, "projection root must not be a symlink" if File.symlink?(@root)
      end

      attr_reader :root

      # `mode` is the default permission for every file; `modes` overrides it
      # per relative path (Kubernetes `defaultMode` and per-item `mode`).
      def write(files, generation: nil, secret: false, mode: nil, modes: {})
        @mutex.synchronize do
          normalized = normalize_files(files)
          per_file_modes = normalize_modes(modes)
          ensure_target!(secret: secret)
          ensure_root!
          generation_name = generation_name(normalized, generation)
          generation_path = File.join(@root, generation_name)
          ensure_generation_directory!(generation_path)
          begin
            normalized.each do |path, content|
              destination = secure_child(generation_path, path)
              FileUtils.mkdir_p(File.dirname(destination))
              flags = File::WRONLY | File::CREAT | File::EXCL
              flags |= File::NOFOLLOW if defined?(File::NOFOLLOW)
              File.open(destination, flags, per_file_modes.fetch(path) { mode || (secret ? 0o400 : 0o444) }) do |file|
                file.write(content)
                file.flush
                file.fsync if @fsync == true
              end
            end
            fsync_directory(generation_path)
            swap_data_link(generation_name)
            remove_stale_exposed_files(normalized.keys)
            expose_files(normalized.keys)
            fsync_directory(@root)
            {"generation" => generation_name, "root" => @root, "files" => normalized.keys.freeze,
             "secret" => secret == true}.freeze
          rescue StandardError
            FileUtils.rm_rf(generation_path) if File.exist?(generation_path) && !File.symlink?(generation_path)
            raise
          end
        end
      end

      def current_generation
        link = File.join(@root, DATA_LINK)
        raise SecurityError, "projected data link was replaced by a non-symlink" if File.exist?(link) && !File.symlink?(link)
        return nil unless File.symlink?(link)

        File.readlink(link)
      rescue SystemCallError => error
        raise SecurityError, "failed to read projected volume generation: #{error.message}"
      end

      def read(path)
        relative = validate_relative(path)
        link = File.join(@root, DATA_LINK)
        raise SecurityError, "projected data link is missing" unless File.symlink?(link)

        File.binread(File.join(@root, DATA_LINK, relative))
      rescue SystemCallError => error
        raise SecurityError, "failed to read projected file #{path.inspect}: #{error.message}"
      end

      def generations
        return [] unless File.directory?(@root)

        Dir.children(@root).grep(/\A\.\.[0-9a-f]+-[0-9a-f]{24}(?:-[0-9a-f]{8})?\z/).sort.freeze
      end

      private

      def ensure_target!(secret:)
        return true unless secret == true

        return if @tmpfs || (@mount_adapter && tmpfs_mount_present?)

        raise SecretPersistenceError, "Secret projection requires an injected tmpfs mount"
      end

      def tmpfs_mount_present?
        return @mount_adapter.tmpfs?(@root) if @mount_adapter.respond_to?(:tmpfs?)
        return @mount_adapter.ensure_tmpfs(@root) if @mount_adapter.respond_to?(:ensure_tmpfs)

        false
      end

      def normalize_modes(modes)
        hash = modes.respond_to?(:to_h) ? modes.to_h : {}
        hash.each_with_object({}) do |(path, value), result|
          next if value.nil?

          integer = Integer(value)
          raise ValidationError, "projected file mode for #{path.inspect} must be between 0 and 0777" unless integer.between?(0, 0o777)

          result[validate_relative(path)] = integer
        end
      rescue ArgumentError, TypeError
        raise ValidationError, "projected file modes must be integers"
      end

      def normalize_files(files)
        hash = files.respond_to?(:to_h) ? files.to_h : files
        raise ValidationError, "projected files must be a map" unless hash.is_a?(Hash)

        hash.each_with_object({}) do |(path, value), result|
          relative = validate_relative(path)
          raise ValidationError, "projected path #{relative.inspect} is reserved" if relative.split("/").any? do |part|
            part.start_with?("..")
          end

          content = value.is_a?(String) ? value.b : String(value).b
          raise ValidationError, "projected file #{relative.inspect} exceeds 1 MiB" if content.bytesize > 1_048_576

          result[relative] = content.freeze
        end.freeze
      end

      def validate_relative(path)
        value = String(path)
        raise PathSecurityError, "projected path must not contain NUL" if value.include?("\0")
        raise PathSecurityError, "projected path must be relative" if value.start_with?("/")

        components = value.split("/")
        raise PathSecurityError, "projected path is empty" if value.empty?
        if components.empty? || components.include?("..") || components.include?(".") || components.any?(&:empty?)
          raise PathSecurityError,
                "projected path contains traversal"
        end

        value
      rescue TypeError
        raise PathSecurityError, "projected path must be a string"
      end

      def generation_name(files, requested)
        value = requested && String(requested)
        if value
          raise ValidationError, "generation contains unsafe characters" unless value.match?(/\A\.[.][A-Za-z0-9_-]{1,128}\z/)

          return value
        end

        timestamp = @clock.call.to_f.to_i.to_s(16)
        # Hashed as bytes: a JSON round-trip refuses binary content
        # (ConfigMap binaryData, binary Secrets) with a GeneratorError.
        digest = Digest::SHA256.new
        files.sort_by(&:first).each do |path, data|
          path_bytes = String(path).b
          data_bytes = String(data).b
          digest.update([path_bytes.bytesize].pack("N")).update(path_bytes)
          digest.update([data_bytes.bytesize].pack("N")).update(data_bytes)
        end
        digest = digest.hexdigest[0, 24]
        candidate = "#{GENERATION_PREFIX}#{timestamp}-#{digest}"
        File.exist?(File.join(@root, candidate)) ? "#{candidate}-#{SecureRandom.hex(4)}" : candidate
      end

      def secure_child(parent, relative)
        ensure_no_symlink_components!(parent, relative)
        destination = File.expand_path(relative, parent)
        prefix = parent.end_with?(File::SEPARATOR) ? parent : "#{parent}#{File::SEPARATOR}"
        raise PathSecurityError, "projected file escaped generation" unless destination.start_with?(prefix)

        destination
      end

      def ensure_root!
        raise PathSecurityError, "projection root must not be a symlink" if File.symlink?(@root)

        FileUtils.mkdir_p(@root)
        raise PathSecurityError, "projection root is not a directory" unless File.directory?(@root)
      rescue SystemCallError => error
        raise PathSecurityError, "projection root could not be prepared: #{error.message}"
      end

      def ensure_generation_directory!(path)
        raise PathSecurityError, "projection generation must not be a symlink" if File.symlink?(path)

        FileUtils.mkdir_p(path)
        raise PathSecurityError, "projection generation is not a directory" unless File.directory?(path)
      rescue SystemCallError => error
        raise PathSecurityError, "projection generation could not be prepared: #{error.message}"
      end

      def ensure_no_symlink_components!(parent, relative)
        current = parent
        relative.split("/")[0...-1].each do |component|
          current = File.join(current, component)
          next unless File.exist?(current)
          raise PathSecurityError, "projected path component #{component.inspect} is a symlink" if File.symlink?(current)
        end
      rescue SystemCallError => error
        raise PathSecurityError, "projected path component validation failed: #{error.message}"
      end

      def swap_data_link(generation_name)
        temporary = File.join(@root, "#{DATA_LINK}.tmp-#{Process.pid}-#{SecureRandom.hex(6)}")
        destination = File.join(@root, DATA_LINK)
        if File.exist?(destination) && !File.symlink?(destination)
          raise PathSecurityError, "projected data link was replaced by a non-symlink"
        end

        File.symlink(generation_name, temporary)
        File.rename(temporary, destination)
      rescue SystemCallError => error
        File.delete(temporary) if temporary && File.symlink?(temporary)
        raise SecurityError, "atomic projected generation swap failed: #{error.message}"
      end

      # kubelet AtomicWriter: only the first path segment of each file is
      # exposed, as a symlink into ..data ("path" -> "..data/path").  A link per
      # nested file ("path/to/x" -> "..data/path/to/x") resolves its relative
      # target from the nested directory and dangles.
      def expose_files(paths)
        paths.map { |relative| relative.split("/").first }.uniq.each do |segment|
          link = File.join(@root, segment)
          if File.exist?(link) && !File.symlink?(link)
            raise PathSecurityError, "projected file #{segment.inspect} was replaced by a non-symlink"
          end

          temporary = "#{link}.tmp-#{Process.pid}-#{SecureRandom.hex(4)}"
          target = File.join(DATA_LINK, segment)
          File.symlink(target, temporary)
          File.rename(temporary, link)
        rescue SystemCallError => error
          File.delete(temporary) if temporary && File.symlink?(temporary)
          raise SecurityError, "projected file link swap failed for #{segment.inspect}: #{error.message}"
        end
      end

      def remove_stale_exposed_files(paths)
        desired = paths.map { |path| path.split("/").first }.uniq.to_h { |path| [path, true] }
        walk_exposed(@root, "", desired)
      end

      def walk_exposed(directory, prefix, desired)
        Dir.children(directory).each do |name|
          next if name == DATA_LINK || generation_directory?(name)

          relative = prefix.empty? ? name : "#{prefix}/#{name}"
          path = File.join(directory, name)
          if File.symlink?(path)
            File.delete(path) unless desired.key?(relative)
          elsif File.directory?(path)
            walk_exposed(path, relative, desired)
            Dir.rmdir(path) if Dir.empty?(path)
          end
        end
      rescue SystemCallError => error
        raise SecurityError, "projected stale-file cleanup failed: #{error.message}"
      end

      def generation_directory?(name)
        name.match?(/\A\.\.[0-9a-f]+-[0-9a-f]{24}(?:-[0-9a-f]{8})?\z/)
      end

      def fsync_directory(path)
        return unless @fsync == true

        directory = File.open(path, File::RDONLY | (defined?(File::O_DIRECTORY) ? File::O_DIRECTORY : 0))
        directory.fsync
        directory.close
      rescue SystemCallError => error
        raise SecurityError, "projected generation durability sync failed: #{error.message}"
      end
    end

    class TokenRotator
      Token = Struct.new(:value, :audience, :pod_uid, :issued_at, :expires_at, keyword_init: true) do
        def to_h
          {"value" => value, "audience" => audience, "podUid" => pod_uid,
           "issuedAt" => issued_at, "expiresAt" => expires_at}
        end

        def remaining(now)
          expires_at.to_f - now.to_f
        end

        def lifetime
          expires_at.to_f - issued_at.to_f
        end

        def rotate_due?(now)
          remaining(now) <= lifetime * 0.2
        end
      end

      def initialize(provider:, clock: -> { Time.now.utc }, minimum_ttl: 60)
        @provider = provider
        @clock = clock
        @minimum_ttl = Integer(minimum_ttl)
        raise ValidationError, "token minimum TTL must be positive" unless @minimum_ttl.positive?
      end

      # An empty audience is the API server's default audience, not an error:
      # a projected serviceAccountToken source without `audience` must mint a
      # token the cluster's own API server accepts.
      def issue(audience:, pod_uid:, ttl: nil)
        audience = audience.nil? || audience.to_s.empty? ? "" : Types.identifier(audience, "token audience")
        pod_uid = Types.identifier(pod_uid, "pod uid")
        issued_at = timestamp(@clock.call)
        begin
          requested_ttl = Integer(ttl || @minimum_ttl)
        rescue ArgumentError, TypeError
          raise ValidationError, "token ttl must be an integer"
        end
        raise ValidationError, "token ttl must be positive" unless requested_ttl.positive?

        raw = if @provider.respond_to?(:issue)
                @provider.issue(audience: audience, pod_uid: pod_uid, ttl: requested_ttl)
              elsif @provider.respond_to?(:call)
                @provider.call(audience: audience, pod_uid: pod_uid, ttl: requested_ttl)
              else
                raise UnsupportedError, "token provider must implement issue or call"
              end
        value, expiry = normalize(raw, issued_at, requested_ttl, audience: audience, pod_uid: pod_uid)
        raise SecurityError, "token provider returned an expired token" unless expiry > issued_at

        Token.new(value: value.freeze, audience: audience.freeze, pod_uid: pod_uid.freeze,
                  issued_at: issued_at, expires_at: expiry).freeze
      end

      def rotate(token, now: @clock.call)
        raise ValidationError, "token must be a Token" unless token.respond_to?(:rotate_due?)
        return token unless token.rotate_due?(timestamp(now))

        # kubelet's token manager re-requests the token with the same
        # expirationSeconds; issuing for the *remaining* time produced a
        # replacement that expired at the very same instant as the original.
        issue(audience: token.audience, pod_uid: token.pod_uid, ttl: [token.lifetime.ceil, @minimum_ttl].max)
      end

      private

      def timestamp(value)
        value.is_a?(Time) ? value.utc : Time.parse(value.to_s).utc
      end

      def normalize(raw, issued_at, ttl, audience:, pod_uid:)
        if raw.respond_to?(:to_h)
          hash = raw.to_h
          value = hash["token"] || hash[:token] || hash["value"] || hash[:value]
          expires = hash["expiresAt"] || hash[:expires_at] || hash["expires_at"]
          raise SecurityError, "token provider returned no token" if value.nil?

          returned_audience = hash["audience"] || hash[:audience]
          returned_pod_uid = hash["podUid"] || hash[:pod_uid] || hash["pod_uid"]
          if returned_audience && returned_audience.to_s != audience.to_s
            raise SecurityError,
                  "token provider returned an unexpected audience"
          end
          if returned_pod_uid && returned_pod_uid.to_s != pod_uid.to_s
            raise SecurityError,
                  "token provider returned an unexpected pod identity"
          end

          expiry = expires.nil? ? issued_at + ttl : timestamp(expires)
        else
          value = raw
          expiry = issued_at + ttl
        end
        raise SecurityError, "token provider returned an empty token" if String(value).empty?

        [String(value), expiry]
      end
    end

    class Projector
      def initialize(writer:, token_rotator: nil, clock: -> { Time.now.utc })
        @writer = writer
        @token_rotator = token_rotator
        @clock = clock
        @token = nil
      end

      attr_reader :writer, :token

      def project(sources:, pod: {}, secret: false, generation: nil, mode: nil, modes: {})
        files = {}
        Array(sources).each do |source|
          source_files = source.respond_to?(:call) ? source.call(pod) : source
          source_files = source_files.to_h if source_files.respond_to?(:to_h)
          raise ValidationError, "projection source must return a map" unless source_files.is_a?(Hash)

          source_files.each do |path, value|
            path = String(path)
            raise ValidationError, "projected path collision at #{path.inspect}" if files.key?(path)

            files[path] = value
          end
        end
        result = @writer.write(files, generation: generation, secret: secret, mode: mode, modes: modes)
        result.merge("token" => @token&.to_h).freeze
      end

      def project_token(audience:, pod_uid:, path: "token", ttl: nil, generation: nil)
        raise UnsupportedError, "token rotator is not configured" unless @token_rotator

        @token = @token_rotator.issue(audience: audience, pod_uid: pod_uid, ttl: ttl)
        @writer.write({path => @token.value}, generation: generation, secret: true).merge("token" => @token.to_h).freeze
      end

      def rotate_token(now: @clock.call, path: "token", generation: nil)
        raise UnsupportedError, "token rotator is not configured" unless @token_rotator
        raise ValidationError, "no projected token exists" unless @token

        rotated = @token_rotator.rotate(@token, now: now)
        return @token.to_h unless rotated != @token

        @token = rotated
        @writer.write({path => @token.value}, generation: generation, secret: true).merge("token" => @token.to_h).freeze
      end
    end

    AtomicProjection = AtomicWriter unless const_defined?(:AtomicProjection, false)
  end
end
