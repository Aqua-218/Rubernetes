# frozen_string_literal: true

# Rootfs and OCI pathname validation.  Mounting is delegated to an injected
# adapter; this class never turns an unsafe archive entry into a host path.

require "digest"

module Rubernetes
  module Runtime
    class Native
      class Filesystem
        class Error < Native::Error; end
        class UnsafeEntry < Error; end
        class DigestMismatch < Error; end

        Workspace = Data.define(:id, :root, :upper, :work, :identity, :image_digest) do
          def to_h
            {"id" => id, "root" => root, "upper" => upper, "work" => work, "identity" => identity, "image_digest" => image_digest}
          end
        end

        def initialize(adapter: nil, root: nil)
          @adapter = adapter
          @root = root && File.expand_path(String(root))
          @workspaces = {}
          @mutex = Mutex.new
        end

        def validate_entry!(path, type: :file, link_target: nil)
          value = String(path)
          raise UnsafeEntry, "filesystem entry contains NUL" if value.include?("\0")
          raise UnsafeEntry, "filesystem entry must be relative" if value.start_with?("/")

          components = value.split("/")
          raise UnsafeEntry, "filesystem entry contains parent traversal" if components.include?("..")
          raise UnsafeEntry, "filesystem entry contains an empty component" if components.any?(&:empty?)
          if %i[character_device block_device fifo socket].include?(type.to_sym)
            raise UnsafeEntry, "device and special file entries are not allowed in a native rootfs"
          end

          if link_target
            target = String(link_target)
            raise UnsafeEntry, "symlink target contains NUL" if target.include?("\0")
            raise UnsafeEntry, "symlink target must remain inside the rootfs" if target.start_with?("/") || target.split("/").include?("..")
          end
          value
        end

        alias validate_path! validate_entry!

        def verify_digest(bytes, digest)
          expected = normalize_digest(digest)
          actual = "sha256:#{Digest::SHA256.hexdigest(String(bytes).b)}"
          raise DigestMismatch, "image digest mismatch: expected #{expected}, got #{actual}" unless secure_compare(expected, actual)

          actual
        end

        def prepare(id:, image_digest:, lowerdirs: [], read_only: false, owner: nil)
          digest = normalize_digest(image_digest)
          identifier = String(id)
          validate_identifier!(identifier)
          if @root
            base = File.join(@root, identifier)
            workspace = Workspace.new(
              id: identifier,
              root: File.join(base, "root"),
              upper: File.join(base, "upper"),
              work: File.join(base, "work"),
              identity: "workspace:#{identifier}:#{digest}",
              image_digest: digest
            )
          else
            workspace = Workspace.new(id: identifier, root: nil, upper: nil, work: nil,
                                      identity: "workspace:#{identifier}:#{digest}", image_digest: digest)
          end
          if @adapter
            arguments = {workspace: workspace, lowerdirs: Array(lowerdirs), read_only: read_only}
            arguments[:owner] = owner if owner
            invoke(:prepare, **arguments)
          end
          @mutex.synchronize { @workspaces[identifier] = workspace }
          workspace
        end

        def cleanup(workspace)
          result = if @adapter
                     invoke(:cleanup, workspace: workspace)
                   elsif workspace.root && File.exist?(workspace.root)
                     raise Error, "filesystem cleanup requires an injected adapter for host paths"
                   else
                     true
                   end
          return false if result == false

          @mutex.synchronize { @workspaces.delete_if { |_id, value| value.identity == workspace.identity } }
          true
        end

        # Re-register a workspace after restart without creating a new
        # directory or changing its image identity.  The host adapter is
        # responsible for mount-table readback; this method preserves the
        # durable workspace identity in the Ruby ownership index.
        def adopt(workspace, namespace: nil, metadata: nil)
          value = workspace.is_a?(Workspace) ? workspace : Workspace.new(**workspace.to_h.transform_keys(&:to_sym))
          normalize_digest(value.image_digest)
          validate_identifier!(value.id)
          if @adapter
            if @adapter.respond_to?(:adopt)
              @adapter.adopt(workspace: value, namespace: namespace, metadata: metadata || {})
            elsif namespace
              raise Error, "filesystem adapter cannot verify an adopted workspace mount"
            end
          end
          @mutex.synchronize { @workspaces[value.id] = value }
          value
        end

        # Host adapters may need the already-created namespace holder to
        # perform the mount inside a private mount namespace.  Pure adapters
        # do not implement activation and therefore retain the no-op path.
        def activate(workspace, namespace:)
          return true unless @adapter.respond_to?(:activate)

          @adapter.activate(workspace, namespace: namespace)
        end

        def workspaces
          @mutex.synchronize { @workspaces.values.map(&:to_h).freeze }
        end

        def resources
          @mutex.synchronize do
            @workspaces.values.map do |workspace|
              workspace.to_h.merge("metadata" => resource_metadata(workspace)).freeze
            end.freeze
          end
        end

        # Return adapter-owned identity fields for durable ownership claims.
        # In particular, the Linux OverlayFS adapter supplies the mount ID and
        # target read back from the holder namespace.  A plain workspace path
        # is intentionally insufficient for restart adoption.
        def resource_metadata(workspace)
          identity = workspace.respond_to?(:identity) ? workspace.identity : String(workspace)
          return {} unless @adapter.respond_to?(:resources)

          entry = Array(@adapter.resources).find do |value|
            hash = value.respond_to?(:to_h) ? value.to_h : value
            (hash["identity"] || hash[:identity]).to_s == identity
          end
          metadata = entry && (entry["metadata"] || entry[:metadata])
          metadata.respond_to?(:to_h) ? metadata.to_h.transform_keys(&:to_s) : {}
        end

        private

        def normalize_digest(value)
          digest = String(value)
          raise DigestMismatch, "image digest must be sha256:<64 hex characters>" unless digest.match?(/\Asha256:[0-9a-fA-F]{64}\z/)

          "sha256:#{digest.delete_prefix("sha256:").downcase}"
        end

        def secure_compare(left, right)
          left.bytesize == right.bytesize && left.bytes.zip(right.bytes).reduce(0) { |result, (a, b)| result | (a ^ b) } == 0
        end

        def validate_identifier!(value)
          raise Error, "workspace identifier is invalid" unless value.match?(/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\z/)
        end

        def invoke(operation, **arguments)
          if @adapter.respond_to?(operation)
            @adapter.public_send(operation, **arguments)
          elsif @adapter.respond_to?(:call)
            @adapter.call(operation, **arguments)
          else
            raise Error, "filesystem adapter cannot #{operation} workspace"
          end
        end
      end

      ImageVerifier = Filesystem unless const_defined?(:ImageVerifier, false)
    end
  end
end
