# frozen_string_literal: true

require "digest"
require "base64"
require "fileutils"
require "monitor"
require "pathname"
require "tmpdir"
require_relative "filesystem_adapter"
require_relative "../node/field_ref"

module Rubernetes
  module Volume
    module AdapterSupport
      module_function

      def call(adapter, method_name, *args, **kwargs)
        return nil unless adapter && adapter.respond_to?(method_name)

        method = adapter.method(method_name)
        if kwargs.empty?
          method.call(*args)
        elsif method.parameters.any? { |kind, _| %i[keyreq keyrest key].include?(kind) }
          method.call(*args, **kwargs)
        elsif args.empty?
          method.call(kwargs)
        else
          method.call(*args, kwargs)
        end
      rescue ArgumentError => error
        # A small number of test/third-party adapters expose a positional
        # request object. Retry only when the signature proves that shape.
        raise error unless kwargs.any? && method.parameters.none? { |kind, _| %i[keyreq keyrest key].include?(kind) }

        method.call(*args, kwargs)
      end

      def result_hash(value)
        return {} if value.nil?
        return value.to_h.transform_keys(&:to_s) if value.respond_to?(:to_h)

        {"value" => value}
      end
    end

    class Backend
      attr_reader :id, :spec, :adapter, :device_adapter, :path_security, :root, :require_real_readback

      def initialize(id:, spec:, adapter: nil, root: File.join(Dir.tmpdir, "rubernetes-volumes"), path_security: nil,
                     mount_adapter: nil, device_adapter: nil, require_real_readback: false)
        @id = Types.identifier(id, "volume id")
        @spec = Types.deep_copy(spec)
        @adapter = adapter || FilesystemAdapter.new(root: root)
        @device_adapter = device_adapter || @adapter
        @root = File.expand_path(root.to_s)
        @path_security = path_security
        @mount_adapter = mount_adapter || @adapter
        @require_real_readback = require_real_readback == true
        FileUtils.mkdir_p(@root) if @adapter.is_a?(FilesystemAdapter)
      end

      def type
        self.class::TYPE
      end

      def secret?
        false
      end

      def persistent?
        false
      end

      def remote?
        false
      end

      def readonly?
        false
      end

      def provision
        source = source_path
        ensure_directory(source)
        {"source" => source, "backend" => type, "readonly" => readonly?, "secret" => secret?}
      end

      def delete
        remove_path(source_path)
        true
      end

      def attach(node:, context: {})
        {"node" => Types.identifier(node, "node"), "source" => source_path, "context" => Types.deep_copy(context)}
      end

      # Recovery hook: a backend whose provisioned source mount is gone from
      # the kernel (the node restarted into a fresh mount namespace) may
      # re-establish it from the durable spec.  The default is nil: the
      # missing mount stays reported and nothing is fabricated.
      def restore_source_mount!
        nil
      end

      def detach(node:, context: {})
        {"node" => Types.identifier(node, "node"), "source" => source_path, "context" => Types.deep_copy(context)}
      end

      def stage(path:, node:, readonly: false, context: {})
        mount_stage(path, source: source_path, readonly: readonly, options: mount_options(context))
      end

      protected def mount_stage(path, source:, readonly:, options:, source_handle: nil, requested_filesystem: filesystem)
        ensure_path!(path)
        # A bind mount's target must be the same kind of object as its source:
        # binding a file (a hostPath onto /etc/hosts, say) over a directory is
        # EINVAL, and so is a bind that never sets MS_BIND because the source
        # happened not to be a directory.
        bind = requested_filesystem.nil?
        source_is_directory = directory_source?(source)
        target_lease = acquire_target_lease(path, directory: bind ? source_is_directory : target_directory?)
        source_handle ||= source_handle_for(source)
        requested_options = options
        if bind
          requested_options = if requested_options.is_a?(Array)
                                requested_options + ["bind"]
                              else
                                requested_options.to_h.merge("bind" => true)
                              end
        end
        mount_arguments = {source: source, target: path, filesystem: requested_filesystem,
                           readonly: readonly || readonly?, options: requested_options, volume_id: id,
                           stage: true, source_handle: source_handle}
        mount_arguments[:target_handle] = target_lease if target_lease
        if @require_real_readback && block_filesystem_mount?(source: source, filesystem: requested_filesystem, bind: bind)
          mount_arguments[:require_filesystem_uuid] = true
        end
        identity = if @mount_adapter.respond_to?(:mount)
                     AdapterSupport.call(@mount_adapter, :mount, **mount_arguments)
                   else
                     {"source" => source, "target" => path, "readonly" => readonly || readonly?}
                   end
        normalized_identity = normalize_mount(identity, path, stage: true)
        mount_identity = descriptor_mount_binding? ? normalized_identity : nil
        verify_target_lease!(target_lease, mount_identity: mount_identity)
        normalized_identity
      ensure
        target_lease&.close
      end

      def unstage(path:, identity: nil, context: {})
        path = ensure_path!(path)
        verify_mount_identity!(path, identity)
        target_lease = acquire_target_lease(path, directory: nil, create: false)
        begin
          result = unmount_owned_target(path, identity: identity, target_lease: target_lease,
                                              operation: "unstage", context: context)
          verify_unmounted_target!(path, identity)
          result
        ensure
          target_lease&.close
        end
      end

      def publish(stage_path:, target:, node:, pod:, readonly: false, sub_path: nil, context: {})
        ensure_path!(target)
        source = stage_path
        parent_handle = nil
        handle = nil
        target_lease = nil
        if sub_path
          raise PathSecurityError, "subPath requires openat2 descriptor validation" unless @path_security

          parent_handle = open_stage_handle(stage_path)
          begin
            # A read-only volume is never modified to satisfy a subPath.
            handle = @path_security.validate_sub_path!(parent_handle, sub_path,
                                                       create: !(readonly || readonly?))
          ensure
            parent_handle.close unless handle && parent_handle.equal?(handle)
            nil
          end
          if handle.respond_to?(:path)
            child_path = handle.path.to_s
            source = child_path.start_with?("/") ? child_path : File.join(stage_path, child_path)
          end
        end
        # The publish is a bind of the staged object, so the container-visible
        # target has to be the same kind: a hostPath onto a file (/etc/hosts)
        # cannot be bound over a directory.  For a subPath the kind is known
        # only once it resolved (kubelet prepareSubpathTarget lstats the
        # source first): creating a directory target for a file that did not
        # exist yet left a stale directory behind, and the retry -- once the
        # init container had written the file -- failed on it.
        target_lease = acquire_target_lease(target, directory: publish_target_directory?(stage_path, sub_path))
        mount_arguments = {source: source, target: target, readonly: readonly || readonly?, volume_id: id,
                           node: node, pod: pod, context: context, source_handle: handle}
        mount_arguments[:target_handle] = target_lease if target_lease
        identity = if @mount_adapter.respond_to?(:bind)
                     AdapterSupport.call(@mount_adapter, :bind, **mount_arguments)
                   elsif @mount_adapter.respond_to?(:mount)
                     AdapterSupport.call(@mount_adapter, :mount, **mount_arguments, filesystem: "bind", options: {"bind" => true},
                                                                                    stage: false)
                   else
                     {"source" => source, "target" => target, "readonly" => readonly || readonly?}
                   end
        result = normalize_mount(identity, target, stage: false)
        mount_identity = descriptor_mount_binding? ? result : nil
        verify_target_lease!(target_lease, mount_identity: mount_identity)
        result["node"] = node.to_s
        result["pod"] = pod_identifier(pod)
        result
      ensure
        handle&.close
        target_lease&.close
      end

      def unpublish(target:, identity: nil, context: {})
        target = ensure_path!(target, teardown: true)
        verify_mount_identity!(target, identity)
        target_lease = with_stale_unmount_fallback(target, identity) { acquire_target_lease(target, directory: nil, create: false) }
        begin
          result = unmount_owned_target(target, identity: identity, target_lease: target_lease,
                                                operation: "unpublish", context: context)
          verify_unmounted_target!(target, identity)
          result
        ensure
          target_lease&.close
        end
      rescue PathSecurityError => error
        raise unless identity_value(identity, "kubeletSubPath") == true && @mount_adapter.is_a?(NativeMountAdapter) &&
                     StaleUnmount.stale_path?(error)

        @mount_adapter.unmount_stale_nfs_subpath(target, identity: identity, path_security: @path_security, volume_id: id)
      end

      def stats(path:, capacity_bytes: nil)
        if @adapter.respond_to?(:stats)
          value = AdapterSupport.call(@adapter, :stats, path: path, volume_id: id, capacity_bytes: capacity_bytes)
          return value if value.is_a?(Stats)

          hash = AdapterSupport.result_hash(value)
          return Stats.new(volume_id: id, used_bytes: hash["usedBytes"] || hash["used_bytes"] || 0,
                           capacity_bytes: hash["capacityBytes"] || hash["capacity_bytes"] || capacity_bytes || 0,
                           available_bytes: hash["availableBytes"] || hash["available_bytes"],
                           inodes_used: hash["inodesUsed"] || hash["inodes_used"] || 0,
                           inodes: hash["inodes"])
        end
        Stats.new(volume_id: id, capacity_bytes: capacity_bytes || 0)
      end

      def expand(capacity_bytes:)
        bytes = Types.parse_capacity(capacity_bytes)
        raise UnsupportedError, "backend #{type} does not provide an expansion adapter" unless @adapter.respond_to?(:expand)

        AdapterSupport.call(@adapter, :expand, source: source_path, capacity_bytes: bytes, volume_id: id)
        bytes
      end

      def snapshot(token: nil, name: nil)
        if @adapter.respond_to?(:snapshot)
          AdapterSupport.call(@adapter, :snapshot, source: source_path, volume_id: id)
        else
          content = snapshot_content
          {"source" => source_path, "digest" => digest_source, "content" => content,
           "contentSha256" => Backend.content_digests(content),
           "contentDigest" => Backend.content_digest(content)}
        end
      end

      # Per-file SHA-256 digests recorded at snapshot time.  They travel in
      # the snapshot catalog so restore can refuse bytes that changed while
      # the catalog was at rest.
      def self.content_digests(content)
        return nil unless content.is_a?(Hash)

        content.keys.map(&:to_s).sort.each_with_object({}) do |relative, result|
          value = content.key?(relative) ? content[relative] : content[relative.to_sym]
          result[relative] = Digest::SHA256.hexdigest(content_bytes(value))
        end
      end

      # Snapshot content travels through JSON catalogs and CSI payloads.  Text
      # stays a plain string; bytes that are not valid UTF-8 are carried as a
      # {"encoding" => "base64", "data" => ...} envelope so the catalog remains
      # valid JSON and the digest still covers the exact file bytes.
      def self.encode_content_value(bytes)
        text = String(bytes).b
        utf8 = text.dup.force_encoding(Encoding::UTF_8)
        return utf8 if utf8.valid_encoding?

        {"encoding" => "base64", "data" => Base64.strict_encode64(text)}
      end

      def self.content_bytes(value)
        if value.respond_to?(:to_h) && !value.is_a?(String)
          hash = value.to_h.transform_keys(&:to_s)
          encoding = hash["encoding"].to_s
          data = hash["data"]
          if encoding.casecmp?("base64") && data.is_a?(String)
            begin
              return Base64.strict_decode64(data)
            rescue ArgumentError => error
              raise SnapshotIntegrityError, "snapshot content is not valid base64: #{error.message}"
            end
          end
          raise SnapshotIntegrityError, "snapshot content entry has an unsupported encoding #{encoding.inspect}"
        end
        String(value).b
      end

      def self.content_digest(content)
        digests = content_digests(content)
        return nil if digests.nil?

        Digest::SHA256.hexdigest(digests.map { |relative, digest| "#{relative}\0#{digest}\n" }.join)
      end

      def self.verify_content_integrity!(content, expected_digests, volume_id: nil)
        return true if expected_digests.nil? || !content.is_a?(Hash)
        raise SnapshotIntegrityError, "snapshot content digests for #{volume_id} must be a map" unless expected_digests.respond_to?(:to_h)

        expected = expected_digests.to_h.transform_keys(&:to_s)
        actual = content_digests(content)
        missing = expected.keys - actual.keys
        extra = actual.keys - expected.keys
        unless missing.empty? && extra.empty?
          raise SnapshotIntegrityError,
                "snapshot content file set changed for #{volume_id}: missing #{missing.inspect}, unexpected #{extra.inspect}"
        end

        corrupted = actual.reject { |relative, digest| expected.fetch(relative).to_s == digest }.keys
        raise SnapshotIntegrityError, "snapshot content digest mismatch for #{volume_id}: #{corrupted.inspect}" unless corrupted.empty?

        true
      end

      def restore(content: nil, content_sha256: nil)
        Backend.verify_content_integrity!(content, content_sha256, volume_id: id)
        provision unless path_exists?(source_path)
        if @adapter.respond_to?(:restore)
          AdapterSupport.call(@adapter, :restore, source: source_path, volume_id: id, content: content)
        elsif content.is_a?(Hash)
          write_snapshot_content(content)
        end
        {"source" => source_path, "backend" => type, "contentDigest" => Backend.content_digest(content)}
      end

      def clone_from(source_backend:)
        if @adapter.respond_to?(:clone) && ![Object, Kernel].include?(@adapter.method(:clone).owner)
          AdapterSupport.call(@adapter, :clone, source: source_backend.source_path, target: source_path,
                                                source_volume_id: source_backend.id, volume_id: id)
        elsif source_backend.respond_to?(:snapshot)
          snapshot = source_backend.snapshot
          content = AdapterSupport.result_hash(snapshot)["content"]
          write_snapshot_content(content) if content.is_a?(Hash)
        end
        provision unless path_exists?(source_path)
        {"source" => source_path, "backend" => type}
      end

      def source_path
        File.join(@root, id)
      end

      def projection_writer(tmpfs: false, mount_adapter: nil)
        AtomicWriter.new(source_path, fsync: false, tmpfs: tmpfs, mount_adapter: mount_adapter,
                                      mountpoints: Types.key(spec, "nestedMountpoints", []))
      end

      # A caller that already resolved the projection (the Node Agent, which
      # applied `items`, key selection and the downward API against the live
      # Pod) hands the finished file map in as `files`; the backend then
      # writes exactly that map.  `defaultMode` and per-file `modes` follow
      # the Kubernetes volume source semantics.
      def precomputed_files
        files = Types.key(spec, "files")
        return nil if files.nil?
        raise ValidationError, "precomputed volume files must be a map" unless files.respond_to?(:to_h)

        result = files.to_h.each_with_object({}) do |(path, content), memo|
          memo[String(path)] = content.is_a?(String) ? content : String(content)
        end
        # Binary content arrives base64-encoded (the node's spec has to be
        # JSON-clean); it is decoded here, at the write.
        binary = Types.key(spec, "binaryFiles")
        if binary.respond_to?(:to_h)
          binary.to_h.each do |path, encoded|
            result[String(path)] = Base64.strict_decode64(String(encoded))
          rescue ArgumentError
            raise ValidationError, "binary volume file #{path.inspect} is not valid base64"
          end
        end
        result
      end

      def default_file_mode
        value = Types.key(spec, "defaultMode", Types.key(spec, "default_mode"))
        value.nil? ? nil : Integer(value)
      rescue ArgumentError, TypeError
        raise ValidationError, "defaultMode must be an integer"
      end

      def file_modes
        value = Types.key(spec, "modes", {})
        return {} unless value.respond_to?(:to_h)

        value.to_h.each_with_object({}) { |(path, mode), result| result[String(path)] = Integer(mode) unless mode.nil? }
      rescue ArgumentError, TypeError
        raise ValidationError, "file modes must be integers"
      end

      def filesystem
        nil
      end

      def mount_options(_context)
        {}
      end

      protected

      def ensure_path!(path, teardown: false)
        value = File.expand_path(String(path))
        return value unless @path_security

        # Backend methods are public lifecycle seams and must carry the same
        # symlink boundary as Node#stage/#publish.  Manager callers already
        # validate targets, but a direct backend invocation must not be able
        # to bypass it (especially for CSI paths that do not yet exist).
        if teardown && @path_security.respond_to?(:validate_unmount_target!)
          @path_security.validate_unmount_target!(value)
        elsif @path_security.respond_to?(:validate_target!)
          @path_security.validate_target!(value)
        else
          @path_security.validate!(Pathname.new(value).relative_path_from(Pathname.new(@path_security.root)).to_s)
        end
        value
      rescue ArgumentError
        raise PathSecurityError, "path #{path.inspect} is outside the configured mount root"
      end

      def open_stage_handle(path)
        # A staged volume's path *is* a mount point, so the final component of
        # this lookup always crosses one.  RESOLVE_NO_XDEV would reject it
        # with EXDEV, which is what made every subPath mount fail; BENEATH and
        # the no-symlink flags still bind the lookup to the configured root.
        # This is the same allowance the CSI target lookup already makes.
        @path_security.open_mount_point(
          Pathname.new(File.expand_path(path)).relative_path_from(Pathname.new(@path_security.root)).to_s
        )
      rescue ArgumentError
        raise PathSecurityError, "stage path #{path.inspect} is outside the configured root"
      end

      def path_exists?(path)
        return true if @adapter.respond_to?(:stat) && AdapterSupport.call(@adapter, :stat, path)

        File.exist?(path)
      rescue SystemCallError
        false
      end

      def snapshot_content
        return nil unless File.directory?(source_path)

        collect_snapshot_files(source_path, source_path)
      rescue SystemCallError
        nil
      end

      def collect_snapshot_files(root, current)
        Dir.children(current).each_with_object({}) do |name, files|
          path = File.join(current, name)
          relative = Pathname.new(path).relative_path_from(Pathname.new(root)).to_s
          stat = File.lstat(path)
          if stat.directory?
            files.merge!(collect_snapshot_files(root, path))
          elsif stat.file?
            files[relative] = Backend.encode_content_value(File.binread(path))
          end
        end
      end

      def write_snapshot_content(content)
        content.each do |relative, value|
          relative = String(relative)
          invalid = relative.start_with?("/") || relative.split("/").any? { |part| part.empty? || part == "." || part == ".." }
          raise PathSecurityError, "snapshot content contains traversal" if invalid

          destination = File.join(source_path, relative)
          prefix = "#{File.expand_path(source_path)}#{File::SEPARATOR}"
          raise PathSecurityError, "snapshot content escaped the volume root" unless File.expand_path(destination).start_with?(prefix)

          FileUtils.mkdir_p(File.dirname(destination))
          File.binwrite(destination, Backend.content_bytes(value))
        end
      end

      def normalize_mount(value, target, stage:)
        hash = AdapterSupport.result_hash(value)
        mount_id = hash["mountId"] || hash["mount_id"]
        filesystem_uuid = if hash.key?("filesystemUuid")
                            hash["filesystemUuid"]
                          elsif hash.key?("filesystem_uuid")
                            hash["filesystem_uuid"]
                          end
        source = hash["source"] || source_path
        normalized_target = hash["target"] || target
        declared_filesystem = filesystem
        filesystem = hash["filesystem"] || hash["fsType"] || declared_filesystem
        device_id = hash["deviceId"] || hash["device_id"]
        root = hash["root"]
        # The kernel source (mountinfo's superblock source) is what unmount
        # verification compares; the requested source is what the volume
        # bound.  They differ only for bind mounts.
        kernel_source = hash["kernelSource"] || hash["kernel_source"]
        bind_identity = bind_mount_identity?(hash, filesystem)
        kernel_source ||= bind_identity ? (hash["sourceIdentity"] || hash["source_identity"]) : source
        uuid_available = hash.key?("filesystemUuidAvailable") ? hash["filesystemUuidAvailable"] == true : filesystem_uuid_present?(filesystem_uuid)
        if @require_real_readback
          missing = {
            "mountId" => mount_id,
            "deviceId" => device_id,
            "root" => root,
            "source" => source,
            "target" => normalized_target,
            "filesystem" => filesystem
          }.filter_map { |field, field_value| field if field_value.nil? || field_value.to_s.empty? }
          raise MountIdentityError, "mount readback for volume #{id} lacks stable fields: #{missing.join(", ")}" unless missing.empty?
          raise MountIdentityError, "mount readback for volume #{id} lacks a kernel major:minor device identity" unless device_id.to_s.match?(/\A\d+:\d+\z/)

          if block_filesystem_mount?(source: source, filesystem: filesystem, root: root,
                                     bind: bind_identity) && !(%w[ext4
                                                                  xfs].include?(filesystem.to_s.downcase) && filesystem_uuid_present?(filesystem_uuid) &&
                                                                    uuid_available)
            raise MountIdentityError, "persistent block mount for volume #{id} requires a real ext4/xfs filesystem UUID"
          end
        end
        filesystem_uuid = nil if bind_identity && @require_real_readback
        filesystem_uuid_available = uuid_available && filesystem_uuid_present?(filesystem_uuid)
        {
          "volumeId" => id, "source" => source, "target" => normalized_target,
          "mountId" => mount_id || "mount-#{Digest::SHA256.hexdigest("#{id}\0#{target}")[0, 20]}",
          "filesystemUuid" => filesystem_uuid || (@require_real_readback ? nil : "fs-#{id}"),
          "filesystemUuidAvailable" => filesystem_uuid_available || (!@require_real_readback && filesystem_uuid.nil?),
          "deviceId" => device_id || "device-#{id}", "root" => root, "filesystem" => filesystem,
          "sourceIdentity" => hash["sourceIdentity"] || hash["source_identity"] || source,
          "kernelSource" => kernel_source, "bind" => bind_identity == true,
          "mountApi" => hash["mountApi"] || hash["mount_api"],
          "stage" => stage == true, "readonly" => hash.key?("readonly") ? hash["readonly"] == true : readonly?,
          "secret" => secret?
        }
      end

      def filesystem_uuid_present?(value)
        !value.nil? && !value.to_s.empty?
      end

      # A persistent block filesystem mount is a superblock mounted from a
      # block device at its root.  A bind of a subtree (root != "/") or an
      # explicitly bind-flagged mount rides on someone else's superblock and
      # is identified by mount ID, device and root instead of a UUID.
      def block_filesystem_mount?(source:, filesystem:, root: nil, bind: false)
        return false unless persistent?
        return false if bind == true
        return true if type.to_s.casecmp?("loopDM")
        return false if root && root.to_s != "/"

        source.to_s.start_with?("/dev/") && %w[ext4 xfs].include?(filesystem.to_s.downcase)
      end

      def bind_mount_identity?(hash, filesystem)
        return hash["bind"] == true if hash.key?("bind")

        options = hash["requestedOptions"] || hash["requested_options"] || hash["options"]
        return true if filesystem.to_s.casecmp?("bind")
        return options.any? { |key, value| key.to_s.casecmp?("bind") && value != false } if options.is_a?(Hash)

        Array(options).any? { |option| option.to_s.split("=", 2).first.casecmp?("bind") }
      end

      def verify_mount_identity!(path, identity)
        hash = identity.respond_to?(:to_h) ? identity.to_h.transform_keys(&:to_s) : nil
        unless hash && %w[mountId deviceId target].all? { |field| Types.present?(hash[field]) }
          raise MountIdentityError, "#{type} mount cleanup requires a validated mount identity"
        end

        expected_target = identity_value(identity, "target")
        raise MountIdentityError, "mount target identity changed for volume #{id}" unless File.expand_path(expected_target.to_s) == File.expand_path(path.to_s)

        observed = mount_identity_at(path)
        if observed
          observed_hash = observed.respond_to?(:to_h) ? observed.to_h.transform_keys(&:to_s) : observed
          %w[mountId filesystemUuid deviceId root source filesystem].each do |field|
            expected = field == "source" ? expected_kernel_source(identity) : identity_value(identity, field)
            actual = if field == "source"
                       # The observation may decorate "source" with the bound
                       # path; the kernel superblock source is what the
                       # recorded identity was taken from.
                       observed_hash["kernelSource"] || observed_hash["kernel_source"] || observed_hash["source"]
                     else
                       observed_hash[field] || observed_hash[field.gsub(/([A-Z])/, '_\\1').downcase]
                     end
            if field == "root" && hash["bind"] == true && descriptor_mount_binding? &&
               observed_hash["mountId"].to_s == hash.fetch("mountId").to_s && Types.deleted_mount_root?(expected, actual)
              next
            end

            raise MountIdentityError, "mount identity changed for #{path}: #{field} mismatch" if expected && actual && expected.to_s != actual.to_s
          end
        end
        true
      end

      # mountinfo reports the superblock source; for a bind mount that is the
      # underlying device, not the directory the volume bound.  Compare the
      # kernel source recorded at mount time so a bind identity stays strict
      # without pretending mountinfo can show the bound path.
      def expected_kernel_source(identity)
        kernel = identity_value(identity, "kernelSource") || identity_value(identity, "kernel_source")
        return kernel unless kernel.nil?
        return identity_value(identity, "sourceIdentity") || identity_value(identity, "source_identity") if identity_value(identity,
                                                                                                                           "bind") == true

        identity_value(identity, "source")
      end

      def identity_value(identity, key)
        return nil unless identity
        return identity[key] if identity.respond_to?(:key?) && identity.key?(key)
        return identity[key.to_sym] if identity.respond_to?(:key?) && identity.key?(key.to_sym)

        identity.respond_to?(key) ? identity.public_send(key) : nil
      end

      def pod_identifier(pod)
        return pod.to_s unless pod.respond_to?(:to_h)

        hash = pod.to_h
        metadata = hash["metadata"] || hash[:metadata] || {}
        metadata["uid"] || metadata[:uid] || metadata["name"] || metadata[:name] || "pod"
      end

      def digest_source
        Digest::SHA256.hexdigest(source_path)
      end

      def source_handle_for(_source)
        nil
      end

      # Native mount effects must resolve the target through a held
      # descriptor.  A pathname-only resolver is acceptable for explicit
      # in-memory test adapters, but never for the production native adapter.
      def acquire_target_lease(path, directory: true, create: true)
        return nil unless @mount_adapter.respond_to?(:target_handle_required?) &&
                          @mount_adapter.target_handle_required?

        unless @path_security && @path_security.respond_to?(:acquire_target!) &&
               @path_security.respond_to?(:descriptor_capable?) && @path_security.descriptor_capable?
          raise PathSecurityError, "native mount targets require a descriptor-capable path lease"
        end

        @path_security.acquire_target!(path, directory: directory, create: create)
      end

      def with_stale_unmount_fallback(path, identity)
        yield
      rescue PathSecurityError => error
        raise unless identity && @mount_adapter.is_a?(NativeMountAdapter) && StaleUnmount.stale_path?(error)

        observed = mount_identity_at(path)
        raise unless observed && %w[nfs nfs4].include?(observed["filesystem"]) &&
                     observed.fetch("mountId").to_s == identity_value(identity, "mountId").to_s

        verify_mount_identity!(path, identity)
        @path_security.acquire_stale_mount_target!(path, observed)
      end

      def verify_target_lease!(lease, mount_identity: nil)
        return true unless lease && lease.respond_to?(:verify_original!)

        verifier = lease.method(:verify_original!)
        accepts_mount_identity = verifier.parameters.any? do |kind, name|
          kind == :keyrest || (%i[key keyreq].include?(kind) && name.to_sym == :mount_identity)
        end
        if accepts_mount_identity
          lease.verify_original!(mounted: true, mount_identity: mount_identity)
        else
          lease.verify_original!(mounted: true)
        end
      end

      def descriptor_mount_binding?
        @mount_adapter.respond_to?(:descriptor_mount_binding?) && @mount_adapter.descriptor_mount_binding? == true
      end

      def ensure_cleanup_result!(result, operation, path)
        return true if [true, 0].include?(result)

        raise CleanupError.new(
          "#{operation} cleanup at #{path.inspect} did not report success",
          details: {"cleanupErrors" => [{"class" => CleanupError.name,
                                         "message" => "adapter returned #{result.inspect}"}]},
          cleanup_errors: []
        )
      end

      def unmount_owned_target(path, identity:, target_lease:, operation:, context: {})
        # After a node crash the mount namespace that held this mount is gone
        # while the durable record still names it.  A native adapter can prove
        # absence from mountinfo; in that case there is nothing to unmount and
        # the cleanup is complete (the ledger entry is still removed by the
        # caller with the expected identity).  Adapters without readback keep
        # the strict path so a lost mount is never assumed.
        if @mount_adapter.respond_to?(:find_mount) && @mount_adapter.respond_to?(:descriptor_mount_binding?) &&
           @mount_adapter.descriptor_mount_binding? == true && mount_identity_at(path).nil?
          return true
        end

        arguments = {
          target: path, mount_id: identity_value(identity, "mountId"), identity: identity,
          volume_id: id, context: context
        }
        arguments[:target_handle] = target_lease if target_lease
        arguments[:isolate_propagation] = true if type == HostPathBackend::TYPE
        result = AdapterSupport.call(@mount_adapter, :unmount, **arguments)
        ensure_cleanup_result!(result, operation, path)
        true
      end

      def verify_unmounted_target!(path, identity)
        return true unless @mount_adapter.respond_to?(:find_mount) || @mount_adapter.respond_to?(:list_mounts)

        observed = mount_identity_at(path)
        return true unless observed

        observed_hash = observed.respond_to?(:to_h) ? observed.to_h.transform_keys(&:to_s) : observed
        expected_id = identity_value(identity, "mountId")
        return true unless expected_id && observed_hash["mountId"].to_s == expected_id.to_s

        raise CleanupError.new(
          "#{type} cleanup at #{path.inspect} remains mounted",
          details: {"cleanupErrors" => [{"class" => MountIdentityError.name,
                                         "message" => "mount #{expected_id} remains mounted"}]},
          cleanup_errors: [MountIdentityError.new("mount #{expected_id} remains mounted")]
        )
      end

      def mount_identity_at(path)
        return @mount_adapter.find_mount(path) if @mount_adapter.respond_to?(:find_mount)
        return nil unless @mount_adapter.respond_to?(:list_mounts)

        normalized = File.expand_path(path.to_s)
        Array(AdapterSupport.call(@mount_adapter, :list_mounts)).find do |entry|
          hash = entry.respond_to?(:to_h) ? entry.to_h : entry
          candidate = hash && (hash["target"] || hash[:target] || hash["mountpoint"] || hash[:mountpoint])
          candidate && File.expand_path(candidate.to_s) == normalized
        end
      end

      def ensure_tmpfs_mount!(path, size_limit: nil)
        target_lease = acquire_target_lease(path, directory: true, create: true)
        begin
          arguments = {size_limit: size_limit, volume_id: id}
          arguments[:target_handle] = target_lease if target_lease
          mounted = if @mount_adapter.respond_to?(:ensure_tmpfs)
                      AdapterSupport.call(@mount_adapter, :ensure_tmpfs, path, **arguments)
                    elsif @mount_adapter.respond_to?(:tmpfs?)
                      @mount_adapter.tmpfs?(path)
                    else
                      false
                    end
          raise SecretPersistenceError, "#{type} volume #{id} is not backed by tmpfs" unless mounted

          identity = mounted.respond_to?(:to_h) ? mounted.to_h : mount_identity_at(path)
          identity ||= mount_identity_at(path)
          unless identity.respond_to?(:to_h) && %w[mountId deviceId target].all? do |field|
            Types.present?(identity.to_h.transform_keys(&:to_s)[field])
          end
            raise MountIdentityError, "#{type} tmpfs mount has no stable identity"
          end

          verify_target_lease!(target_lease, mount_identity: descriptor_mount_binding? ? identity : nil)
          identity
        ensure
          target_lease&.close
        end
      end

      def delete_tmpfs_mount!(path, identity:)
        verify_mount_identity!(path, identity)
        target_lease = acquire_target_lease(path, directory: nil, create: false)
        begin
          unmount_owned_target(path, identity: identity, target_lease: target_lease, operation: "delete")
          verify_unmounted_target!(path, identity)
        ensure
          target_lease&.close
        end
      end

      def target_directory?
        !Types.key(spec, "volumeMode", "Filesystem").to_s.casecmp?("Block")
      end

      # A publish binds what was staged.  A sub-path names something inside a
      # directory, so it follows that object's kind; otherwise the staged
      # object itself decides.
      def publish_target_directory?(stage_path, sub_path)
        return target_directory? unless target_directory?

        probe = sub_path.to_s.empty? ? stage_path : File.join(stage_path.to_s, sub_path.to_s)
        return true unless File.exist?(probe)

        File.directory?(probe)
      rescue SystemCallError
        target_directory?
      end

      def directory_source?(source)
        return false if source.to_s.start_with?("/dev/")
        return true if @adapter.respond_to?(:stat) && AdapterSupport.call(@adapter, :stat, source).respond_to?(:directory?)

        File.directory?(source)
      rescue SystemCallError
        false
      end

      def ensure_directory(path, mode: nil)
        if @adapter.respond_to?(:mkdir)
          AdapterSupport.call(@adapter, :mkdir, path)
        else
          FileUtils.mkdir_p(path)
        end
        raise MountIdentityError, "volume source #{path.inspect} is not a directory" unless File.directory?(path)

        # The umask has already applied; set the mode explicitly (kubelet's
        # emptyDir setupDir does the same so a non-root container can write).
        File.chmod(mode, path) if mode && File.stat(path).mode & 0o7777 != mode
        true
      rescue SystemCallError => error
        raise MountIdentityError, "volume source #{path.inspect} could not be prepared: #{error.message}", cause: error
      end

      def remove_path(path)
        result = if @adapter.respond_to?(:remove)
                   AdapterSupport.call(@adapter, :remove, path)
                 else
                   # FileUtils.rm_rf returns the path list, never a status;
                   # the kernel readback below is the success signal.
                   FileUtils.rm_rf(path)
                   !File.exist?(path) && !File.symlink?(path)
                 end
        [true, 0].include?(result) || raise(CleanupError.new(
          "volume source #{path.inspect} removal did not report success",
          details: {"cleanupErrors" => [{"class" => CleanupError.name,
                                         "message" => "adapter returned #{result.inspect}"}]},
          cleanup_errors: []
        ))
      rescue SystemCallError => error
        raise MountIdentityError, "volume source #{path.inspect} could not be removed: #{error.message}", cause: error
      end
    end

    class EmptyDirBackend < Backend
      TYPE = "emptyDir"
      # pkg/volume/emptydir: world-writable so any runAsUser can use it.
      EMPTY_DIR_MODE = 0o777
      TMPFS_ROOT_MODE = 0o1777

      def initialize(project_quota: nil, **)
        super(**)
        @project_quota = project_quota
      end

      def provision
        medium = Types.key(spec, "medium", "").to_s
        size_limit = Types.key(spec, "sizeLimit")
        mount_identity = nil
        if medium.casecmp?("Memory")
          raise UnsupportedError, "emptyDir medium Memory requires a tmpfs-capable mount adapter" unless @mount_adapter.respond_to?(:ensure_tmpfs)

          mount_identity = ensure_tmpfs_mount!(source_path, size_limit: size_limit)
          File.chmod(TMPFS_ROOT_MODE, source_path) if File.directory?(source_path)
        else
          project = @project_quota&.provision(source_path) if medium.empty? && Types.key(spec, "quotaMonitor") == true
          ensure_directory(source_path, mode: EMPTY_DIR_MODE)
        end
        @mount_identity = mount_identity
        result = {"source" => source_path, "backend" => type, "medium" => medium, "sizeLimit" => size_limit, "mountIdentity" => mount_identity}
        result["projectQuotaId"] = project if project
        result
      end

      def delete
        medium = Types.key(spec, "medium", "").to_s
        delete_tmpfs_mount!(source_path, identity: mount_identity_for_cleanup) if medium.casecmp?("Memory")
        remove_path(source_path)
      end

      # A Memory-medium emptyDir lives on tmpfs; after a node crash its content
      # is gone by definition (Kubernetes documents the same loss), so the
      # empty tmpfs is re-created and its fresh kernel identity returned.
      def restore_source_mount!
        medium = Types.key(spec, "medium", "").to_s
        return nil unless medium.casecmp?("Memory")
        return nil unless @mount_adapter.respond_to?(:ensure_tmpfs)

        @mount_identity = ensure_tmpfs_mount!(source_path, size_limit: Types.key(spec, "sizeLimit"))
      end

      private

      def mount_identity_for_cleanup
        @mount_identity || Types.key(Types.key(spec, "backendResult", {}), "mountIdentity")
      end
    end

    class HostPathBackend < Backend
      TYPE = "hostPath"
      VALID_TYPES = %w[Directory DirectoryOrCreate File FileOrCreate Socket CharDevice BlockDevice].freeze
      # The CRI bind mount creates a missing source directory for an unset HostPath type.
      CREATE_TYPES = ["", "DirectoryOrCreate", "FileOrCreate"].freeze

      def initialize(**kwargs)
        super
        @host_handle = nil
        @host_source_path = nil
      end

      def source_path
        return @host_source_path if @host_source_path && @host_handle

        kind = host_path_type
        validate_host_path_type!(kind)
        path = raw_host_path
        handle = open_host_handle(path, kind: kind, allow_missing: false)
        pin_host_source(handle, path, kind)
      end

      def provision
        kind = host_path_type
        validate_host_path_type!(kind)
        path = raw_host_path
        handle = open_host_handle(path, kind: kind, allow_missing: CREATE_TYPES.include?(kind))
        if handle.nil?
          validate_create_parent!(path)
          create_host_path!(path, kind)
          handle = open_host_handle(path, kind: kind, allow_missing: false)
        end

        {"source" => pin_host_source(handle, path, kind), "backend" => type, "type" => kind}
      end

      def delete
        # HostPath is user-owned and is never removed as part of volume cleanup.
        @host_handle&.close
        @host_handle = nil
        @host_source_path = nil
        true
      end

      def persistent?
        true
      end

      protected

      # The stage pins the source inode for later verification. It must not
      # retain the host mount's peer group, where unpublishing could tear
      # down a host submount that arrived after this shallow bind.
      def mount_options(_context)
        {"private" => true}
      end

      def source_handle_for(_source)
        @host_handle
      end

      private

      def pin_host_source(handle, path, kind)
        resolved = resolved_host_path(handle, path)
        validate_host_stat!(host_path_stat(handle, resolved), resolved, kind)
        @host_handle = handle
        @host_source_path = resolved
      rescue StandardError
        handle.close
        raise
      end

      def host_path_type
        Types.key(spec, "type", "").to_s
      end

      def validate_host_path_type!(kind)
        return true if kind.empty? || VALID_TYPES.include?(kind)

        raise ValidationError, "unsupported hostPath type #{kind.inspect}"
      end

      def raw_host_path
        value = Types.key(spec, "path") || Types.key(spec, "source")
        raise ValidationError, "hostPath requires a path" unless Types.present?(value)
        raise PathSecurityError, "hostPath requires an openat2 path validator" unless @path_security

        value = String(value)
        @path_security.validate!(value, allow_absolute: true)
        host_realpath(value.start_with?("/") ? File.expand_path(value) : File.join(@path_security.root, value))
      rescue TypeError
        raise PathSecurityError, "hostPath path must be a string"
      end

      # kubelet follows symlinks on a hostPath (os.Stat / MkdirAll on the
      # host's own filesystem), so `/var/run/cilium` on a host where
      # /var/run -> /run is /run/cilium.  The descriptor walk below refuses
      # symlinks (RESOLVE_NO_SYMLINKS), which turned every such hostPath into
      # ELOOP and no Pod could mount it.  The existing prefix is resolved
      # to its real path on the host first -- the one place where a symlink
      # is trusted, because the path is the operator's -- and the
      # not-yet-existing tail (DirectoryOrCreate) stays literal; the
      # symlink-free result is then opened through openat2 as before.
      def host_realpath(path)
        existing = path
        tail = []
        until File.exist?(existing) || existing == "/"
          tail.unshift(File.basename(existing))
          existing = File.dirname(existing)
        end
        File.join(File.realpath(existing), *tail)
      rescue SystemCallError
        path
      end

      def open_host_handle(path, kind:, allow_missing:)
        handle = @path_security.validate_host_path!(
          path, flags: host_open_flags(kind), resource_id: "hostPath:#{id}", block_device: kind == "BlockDevice"
        )
        host_path_stat(handle, path)
        handle
      rescue PathSecurityError => error
        if allow_missing && missing_path_error?(error)
          handle&.close
          return nil
        end

        raise
      rescue SystemCallError => error
        if allow_missing && error.is_a?(Errno::ENOENT)
          handle&.close
          return nil
        end

        raise PathSecurityError, "hostPath #{path.inspect} could not be inspected: #{error.message}", cause: error
      end

      def host_open_flags(_kind)
        return nil unless defined?(Rubernetes::Platform::Linux::Openat2::O_PATH)

        Rubernetes::Platform::Linux::Openat2::O_PATH
      end

      def host_path_stat(handle, path)
        return handle.stat if handle.respond_to?(:stat)

        File.stat(path)
      rescue SystemCallError
        raise
      rescue StandardError => error
        raise PathSecurityError, "hostPath #{path.inspect} descriptor could not be inspected: #{error.message}", cause: error
      end

      def resolved_host_path(handle, fallback)
        if handle.respond_to?(:root) && handle.root && handle.respond_to?(:path) && handle.path
          return File.expand_path(File.join(handle.root.to_s, handle.path.to_s))
        end

        fallback
      end

      def validate_host_stat!(stat, path, kind)
        return true if kind.empty?

        predicate = case kind
                    when "Directory", "DirectoryOrCreate" then :directory?
                    when "File", "FileOrCreate" then :file?
                    when "Socket" then :socket?
                    when "CharDevice" then :chardev?
                    when "BlockDevice" then :blockdev?
                    else
                      raise ValidationError, "unsupported hostPath type #{kind.inspect}"
                    end
        return true if stat.respond_to?(predicate) && stat.public_send(predicate)

        raise ValidationError, "hostPath #{path} does not match type #{kind}"
      end

      def validate_create_parent!(path)
        parent = File.dirname(path)
        root = @path_security.root
        loop do
          return true if parent == root

          handle = open_host_handle(parent, kind: "Directory", allow_missing: true)
          if handle
            begin
              validate_host_stat!(host_path_stat(handle, parent), parent, "Directory")
            ensure
              handle.close
            end
            return true
          end

          next_parent = File.dirname(parent)
          raise PathSecurityError, "hostPath parent #{parent.inspect} is outside the configured root" if next_parent == parent

          parent = next_parent
        end
      end

      def create_host_path!(path, kind)
        case kind
        when "", "DirectoryOrCreate"
          if @adapter.respond_to?(:mkdir)
            AdapterSupport.call(@adapter, :mkdir, path, mode: 0o755)
          else
            FileUtils.mkdir_p(path, mode: 0o755)
          end
        when "FileOrCreate"
          if @adapter.respond_to?(:create_file)
            AdapterSupport.call(@adapter, :create_file, path, mode: 0o640)
          else
            File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o640) { |file| file.write("") }
          end
        else
          raise PathSecurityError, "hostPath #{path} is missing and type #{kind.inspect} is not creatable"
        end
      end

      def missing_path_error?(error)
        current = error
        seen = {}.compare_by_identity
        while current && !seen[current]
          return true if current.is_a?(Errno::ENOENT)
          return true if current.respond_to?(:errno) && current.errno.to_i == Errno::ENOENT::Errno

          seen[current] = true
          current = current.respond_to?(:cause) ? current.cause : nil
        end
        false
      end
    end

    class ConfigMapBackend < Backend
      TYPE = "configMap"

      def initialize(**kwargs)
        super
        @writer = Types.key(spec, "writer") || projection_writer
      end

      def provision
        files = precomputed_files || begin
          data = Types.key(spec, "data", {})
          binary = Types.key(spec, "binaryData", {})
          data.to_h.merge(decode_binary(binary.to_h))
        end
        @writer.write(files, secret: false, mode: default_file_mode, modes: file_modes)
        {"source" => source_path, "backend" => type, "generation" => @writer.current_generation}
      end

      def update(data: {}, binary_data: {}, files: nil, generation: nil)
        files ||= data.to_h.merge(decode_binary(binary_data.to_h))
        @writer.write(files, generation: generation, secret: false, mode: default_file_mode, modes: file_modes)
      end

      private

      def decode_binary(binary)
        binary.each_with_object({}) do |(path, encoded), result|
          value = String(encoded)
          begin
            result[path] = Base64.strict_decode64(value)
          rescue ArgumentError
            raise ValidationError, "ConfigMap binaryData for #{path.inspect} is not valid base64"
          end
        end
      end
    end

    # Secret, downwardAPI and projected use the kubelet's memory-backed emptyDir.
    class MemoryProjectionBackend < Backend
      def initialize(**kwargs)
        super
        previous = Types.key(spec, "backendResult")
        @mount_identity = Types.key(previous || {}, "mountIdentity")
        # A running Pod from an older node can still have a read-only bind
        # of the public projection's directory. Refresh its existing files.
        @legacy_directory = previous && @mount_identity.nil? && !secret?
      end

      def restore_source_mount!
        ensure_tmpfs! unless @legacy_directory
      end

      def published_generation?
        File.symlink?(File.join(source_path, AtomicWriter::DATA_LINK))
      end

      def delete
        if @mount_identity
          delete_tmpfs_mount!(source_path, identity: @mount_identity)
        elsif @legacy_directory
          raise MountIdentityError, "unexpected mount on legacy #{type} volume #{id}" if mount_identity_at(source_path)
        else
          # Provisioning can fail before it mounts anything (for example, a
          # bound TokenRequest after Pod deletion). rmdir also refuses an
          # unrecorded live mount or a nonempty directory.
          return discard_unmounted_directory
        end
        remove_path(source_path)
      end

      private

      def downward_api_files(source)
        pod = Types.key(spec, "pod", {})
        allocatable = Types.key(spec, "nodeAllocatable")
        modes = file_modes
        fallback = default_file_mode || 0o644
        Array(Types.key(source, "items", [])).to_h do |item|
          path = Types.key(item, "path")
          bytes = Rubernetes::Node::FieldRef.resolve_item(item, pod, node_allocatable: allocatable)
          mode = Types.key(item, "mode") || modes.fetch(path, fallback)
          [path, AtomicWriter::FileContent.new(bytes, Integer(mode), nil, nil)]
        end
      rescue Rubernetes::Node::FieldRef::Error => error
        raise ValidationError, error.message
      end

      def discard_unmounted_directory
        raise MountIdentityError, "unrecorded mount on #{type} volume #{id}" if mount_identity_at(source_path)

        begin
          Dir.rmdir(source_path)
        rescue Errno::ENOENT
          # This declaration failed before creating its directory.
        end
        true
      end

      def ensure_tmpfs!
        verify_mount_identity!(source_path, @mount_identity) if @mount_identity
        @mount_identity = ensure_tmpfs_mount!(source_path)
      end
    end

    class SecretBackend < MemoryProjectionBackend
      TYPE = "secret"

      def initialize(**kwargs)
        super
        @tmpfs = Types.key(spec, "tmpfs", true) == true
        @writer = Types.key(spec, "writer") || projection_writer(tmpfs: @tmpfs, mount_adapter: @mount_adapter)
      end

      def secret?
        true
      end

      def provision
        mount_identity = ensure_tmpfs!
        files = precomputed_files || begin
          data = Types.key(spec, "data", {})
          string_data = Types.key(spec, "stringData", {})
          decode_data(data.to_h).merge(string_data.to_h)
        end
        @writer.write(files, secret: true, mode: default_file_mode, modes: file_modes)
        {"source" => source_path, "backend" => type, "generation" => @writer.current_generation, "tmpfs" => true,
         "mountIdentity" => mount_identity}
      end

      def update(data: {}, string_data: {}, files: nil, generation: nil)
        ensure_tmpfs!
        files ||= decode_data(data.to_h).merge(string_data.to_h)
        @writer.write(files, generation: generation, secret: true, mode: default_file_mode, modes: file_modes)
      end

      private

      def decode_data(data)
        data.each_with_object({}) do |(path, value), result|
          encoded = String(value)
          begin
            decoded = Base64.strict_decode64(encoded)
            result[path] = [decoded].pack("m0").delete("\n") == encoded.delete("\n") ? decoded : encoded
          rescue ArgumentError
            raise ValidationError, "Secret data for #{path.inspect} is not valid base64"
          end
        end
      end
    end

    class DownwardAPIBackend < MemoryProjectionBackend
      TYPE = "downwardAPI"

      def provision
        files = precomputed_files || downward_api_files(spec)
        mount_identity = ensure_tmpfs!
        writer = Types.key(spec, "writer") || projection_writer
        writer.write(files, secret: false, mode: default_file_mode, modes: file_modes)
        {"source" => source_path, "backend" => type, "generation" => writer.current_generation, "mountIdentity" => mount_identity}
      end

      def update(files:, generation: nil)
        ensure_tmpfs! unless @legacy_directory
        writer = Types.key(spec, "writer") || projection_writer
        writer.write(files, generation: generation, secret: false, mode: default_file_mode, modes: file_modes)
      end
    end

    class ProjectedBackend < MemoryProjectionBackend
      TYPE = "projected"

      class << self
        # The node's PodCertificateManager (Node::PodVolumes#pod_certificates=).
        attr_accessor :pod_certificate_provider

        def service_account_token_source?(sources)
          Array(sources).any? do |source|
            value = source.respond_to?(:to_h) ? source.to_h : source
            value.respond_to?(:key?) && (value.key?("serviceAccountToken") || value.key?(:serviceAccountToken))
          end
        end

        def credential_ownership(pod)
          pod_spec = Types.key(pod, "spec", {})
          security_context = Types.key(pod_spec, "securityContext", {})
          pod_user = Types.key(security_context, "runAsUser")
          users = %w[initContainers containers ephemeralContainers].flat_map do |kind|
            Array(Types.key(pod_spec, kind)).map do |container|
              Types.key(Types.key(container, "securityContext", {}), "runAsUser") || pod_user
            end
          end.uniq
          {"fsUser" => (users.first if users.one?), "fsGroup" => Types.key(security_context, "fsGroup")}.compact
        end
      end

      def initialize(**kwargs)
        super
        @token_rotator = Types.key(spec, "tokenRotator")
        # The provider object never reaches the ledger: a backend rebuilt
        # from a durable record finds the node's manager here.
        @pod_certificates = Types.key(spec, "podCertificateProvider") || self.class.pod_certificate_provider
        @certificate_versions = {}
        @sources = Array(Types.key(spec, "sources", []))
        @tokens = {}
        ownership = Types.key(spec, "credentialOwnership") || self.class.credential_ownership(Types.key(spec, "pod", {}))
        @credential_owner, @credential_group = ownership.values_at("fsUser", "fsGroup")
        @projector = Types.key(spec, "projector") || Projector.new(writer: projection_writer(mount_adapter: @mount_adapter),
                                                                   token_rotator: @token_rotator)
      end

      def secret?
        return true if Types.key(spec, "secret", false) == true

        sensitive_sources?(Types.key(spec, "sources", []))
      end

      def provision
        result = write_sources(@sources)
        result.merge("mountIdentity" => @mount_identity, "source" => source_path, "backend" => type)
      end

      def update(sources:, generation: nil)
        write_sources(sources, generation: generation)
      end

      def token
        @tokens.values.last
      end

      def token_rotation_due?(now = Time.now.utc)
        timestamp = now.respond_to?(:utc) ? now.utc : Time.at(now.to_f).utc
        @tokens.each_value.any? { |issued| issued.respond_to?(:rotate_due?) && issued.rotate_due?(timestamp) }
      end

      def service_account_token_source?
        self.class.service_account_token_source?(Types.key(spec, "sources", []))
      end

      def rotate_token(**options)
        return @projector.rotate_token(**options) unless @token_rotator && token

        now = Types.key(options, "now", Time.now.utc)
        rotated = @tokens.transform_values { |issued| @token_rotator.rotate(issued, now: now) }
        return token.to_h.merge("rotated" => false) if rotated == @tokens

        write_sources(@sources, generation: options[:generation], tokens: rotated).merge("token" => token.to_h).freeze
      end

      private

      def projected_credential(content)
        return content if @credential_owner.nil? && @credential_group.nil?

        # Publish the same permissions as the kubelet's fsGroup pass before
        # exposing the new generation, including during a token refresh.
        mode = @credential_group.nil? ? 0o600 : 0o640
        AtomicWriter::FileContent.new(content, mode, @credential_owner, @credential_group)
      end

      def sensitive_sources?(sources)
        Array(sources).any? do |source|
          source = source.to_h if source.respond_to?(:to_h)
          next false unless source.is_a?(Hash)

          %w[secret serviceAccountToken podCertificate].any? { |kind| Types.key(source, kind) }
        end
      end

      def write_sources(sources, generation: nil, tokens: @tokens)
        if @legacy_directory && sensitive_sources?(sources)
          raise SecretPersistenceError, "legacy disk-backed volume #{id} must be remounted before publishing credentials"
        end

        issued = {}
        versions = {}
        normalized = normalize_sources(sources, tokens, issued, versions)
        ensure_tmpfs! unless @legacy_directory
        result = @projector.project(sources: normalized, pod: Types.key(spec, "pod", {}), secret: secret?, generation: generation,
                                    mode: default_file_mode, modes: file_modes)
        @sources = sources
        @tokens = issued
        @certificate_versions = versions
        result
      end

      def with_item_modes(files, source)
        modes = Types.key(source, "modes")
        return files unless modes

        files.to_h do |path, value|
          mode = modes.fetch(path) { default_file_mode }
          [path, mode.nil? ? value : AtomicWriter::FileContent.new(value, mode, nil, nil)]
        end
      end

      def normalize_sources(sources, tokens, issued, versions)
        sources.map do |source|
          value = source.respond_to?(:to_h) ? source.to_h : source
          next value unless value.is_a?(Hash)

          if value.key?("configMap") || value.key?(:configMap)
            inner = Types.key(value, "configMap", {})
            files = Types.key(inner, "data", {}).to_h.merge(decode_binary(Types.key(inner, "binaryData", {}).to_h))
            with_item_modes(files, inner)
          elsif value.key?("secret") || value.key?(:secret)
            inner = Types.key(value, "secret", {})
            files = decode_secret(Types.key(inner, "data", {}).to_h).merge(Types.key(inner, "stringData", {}).to_h)
            with_item_modes(files, inner)
          elsif value.key?("downwardAPI") || value.key?(:downwardAPI)
            downward_api_files(Types.key(value, "downwardAPI", {}))
          elsif value.key?("serviceAccountToken") || value.key?(:serviceAccountToken)
            inner = Types.key(value, "serviceAccountToken", {})
            raise SecretPersistenceError, "projected service account token requires a token rotator" unless @token_rotator

            audience = Types.key(inner, "audience")
            ttl = Types.key(inner, "expirationSeconds") || ServiceAccountTokenProvider::DEFAULT_TTL_SECONDS
            key = [audience, ttl]
            issued[key] ||= tokens[key] || @token_rotator.issue(audience: audience, pod_uid: Types.key(spec, "podUid", "pod"), ttl: ttl)
            current = issued.fetch(key)
            content = current.respond_to?(:value) ? current.value : Types.key(current, "value")
            {Types.key(inner, "path", "token").to_s => projected_credential(content)}
          elsif value.key?("clusterTrustBundle") || value.key?(:clusterTrustBundle)
            Types.key(value, "clusterTrustBundle", {}).transform_values { |content| projected_credential(content) }
          elsif value.key?("podCertificate") || value.key?(:podCertificate)
            pod_certificate_files(Types.key(value, "podCertificate", {}), versions)
          else
            value
          end
        end
      end

      # A podCertificate source: the credential bundle the kubelet's
      # PodCertificateManager holds for this projection (not ready: the
      # volume setup fails and is retried, as upstream's).
      def pod_certificate_files(inner, versions)
        provider = @pod_certificates
        raise SecretPersistenceError, "projected podCertificate requires the kubelet's PodCertificateManager" unless provider

        pod = Types.key(spec, "pod", {})
        volume_name = Types.key(inner, "volumeName", Types.key(spec, "name", "")).to_s
        index = Types.key(inner, "sourceIndex", 0).to_i
        source = inner.respond_to?(:to_h) ? inner.to_h : {}
        key_pem, chain_pem = begin
          provider.credential_bundle(pod, volume_name, index, source)
        rescue StandardError => error
          raise PodCertificateNotReadyError, "podCertificate #{volume_name}[#{index}]: #{error.message}"
        end
        versions[index] = provider.respond_to?(:version) ? provider.version(pod, volume_name, index) : 1
        files = {}
        bundle_path = Types.key(inner, "credentialBundlePath", nil).to_s
        files[bundle_path] = "#{key_pem}#{chain_pem}" unless bundle_path.empty?
        key_path = Types.key(inner, "keyPath", nil).to_s
        files[key_path] = key_pem unless key_path.empty?
        chain_path = Types.key(inner, "certificateChainPath", nil).to_s
        files[chain_path] = chain_pem unless chain_path.empty?
        files.transform_values { |content| projected_credential(content) }
      end

      def pod_certificate_sources
        Array(Types.key(spec, "sources", [])).filter_map do |source|
          value = source.respond_to?(:to_h) ? source.to_h : source
          next unless value.respond_to?(:key?) && (value.key?("podCertificate") || value.key?(:podCertificate))

          Types.key(value, "podCertificate", {})
        end
      end

      # A refreshed certificate was issued since the files were written.
      def pod_certificate_refresh_due?
        provider = @pod_certificates
        return false unless provider.respond_to?(:version)

        sources = pod_certificate_sources
        return false if sources.empty?
        # A backend rebuilt after a restart holds no versions: re-project once.
        return true if @certificate_versions.empty?

        pod = Types.key(spec, "pod", {})
        sources.any? do |inner|
          index = Types.key(inner, "sourceIndex", 0).to_i
          provider.version(pod, Types.key(inner, "volumeName", Types.key(spec, "name", "")).to_s, index) != @certificate_versions[index]
        end
      end

      # Rewrite the projection with the current credential bundles.
      def refresh_pod_certificates(generation: nil)
        write_sources(@sources, generation: generation)
      end

      public :pod_certificate_refresh_due?, :refresh_pod_certificates, :pod_certificate_sources

      def decode_binary(values)
        values.each_with_object({}) do |(path, encoded), result|
          result[path] = Base64.strict_decode64(String(encoded))
        rescue ArgumentError
          raise ValidationError, "projected ConfigMap binaryData for #{path.inspect} is not valid base64"
        end
      end

      def decode_secret(values)
        values.each_with_object({}) do |(path, encoded), result|
          result[path] = Base64.strict_decode64(String(encoded))
        rescue ArgumentError
          raise ValidationError, "projected Secret data for #{path.inspect} is not valid base64"
        end
      end
    end

    class ImageBackend < Backend
      TYPE = "image"

      def readonly?
        true
      end

      def persistent?
        true
      end

      def provision
        image = Types.key(spec, "image") || Types.key(spec, "reference")
        digest = Types.key(spec, "digest") || image.to_s[/@((?:sha256|sha512):[0-9a-f]+)\z/i, 1]
        raise ValidationError, "image volume requires an immutable digest" unless digest.to_s.match?(/\Asha256:[0-9a-f]{64}\z/i)

        if @adapter.respond_to?(:verify_image)
          verified = AdapterSupport.call(@adapter, :verify_image, image: image, digest: digest, volume_id: id)
          verified_digest = verified.respond_to?(:to_h) ? (verified.to_h["digest"] || verified.to_h[:digest]) : verified
          valid = verified == true || verified_digest.to_s.casecmp?(digest.to_s)
          raise SecurityError, "image volume digest verification failed" unless valid
        end
        # The volume IS the image's unpacked filesystem (kubelet mounts the
        # pulled image read-only); an empty directory in its place made
        # "[sig-node] ImageVolume" find no /volume/data.json.  A spec without
        # a rootfs (unit fixtures) keeps the empty staging directory.
        rootfs = Types.key(spec, "rootfs").to_s
        if rootfs.empty?
          @rootfs_source = nil
          ensure_directory(source_path)
        else
          raise ValidationError, "image volume rootfs #{rootfs.inspect} is not a directory" unless File.directory?(rootfs)

          @rootfs_source = File.expand_path(rootfs)
        end
        {"source" => source_path, "backend" => type, "image" => image, "digest" => digest, "readonly" => true}
      end

      # The manager binds source_path (as it does a hostPath's host
      # directory): the pinned rootfs is the source, not a staging directory
      # under the volume root.
      def source_path
        @rootfs_source || super
      end
    end

    require_relative "local_backend"

    class LoopDMBackend < Backend
      TYPE = "loopDM"

      def initialize(**kwargs)
        super
        result = Types.key(spec, "backendResult", {})
        loop_info = Types.key(result, "loop", {})
        dm_info = Types.key(result, "deviceMapper", {})
        @loop_id = Types.key(loop_info, "id", Types.key(loop_info, "device"))
        @dm_id = Types.key(dm_info, "id", Types.key(dm_info, "device"))
        # The durable identities (loop number, backing inode, dm uuid) are
        # kept so a post-restart cleanup verifies the device it releases is
        # still the one this volume created, not a re-used loop number.
        @loop_identity = loop_info.respond_to?(:to_h) && !loop_info.to_h.empty? ? Types.deep_copy(loop_info.to_h) : nil
        @dm_identity = dm_info.respond_to?(:to_h) && !dm_info.to_h.empty? ? Types.deep_copy(dm_info.to_h) : nil
        @device_source = Types.key(result, "source")
      end

      def persistent?
        true
      end

      def provision
        image = Types.key(spec, "path") || File.join(@root, "#{id}.img")
        size = Types.parse_capacity(Types.key(spec, "size") || Types.key(spec, "capacity") || 1)
        loop_device = if @device_adapter.respond_to?(:create_loop)
                        AdapterSupport.call(@device_adapter, :create_loop, path: image, volume_id: id, size_bytes: size)
                      else
                        raise UnsupportedError, "loop-DM backend requires an injected loop adapter"
                      end
        loop_id = AdapterSupport.result_hash(loop_device)["id"] || AdapterSupport.result_hash(loop_device)["device"]
        raise MountIdentityError, "loop adapter returned no device identity" if loop_id.to_s.empty?

        @loop_id = loop_id
        @loop_identity = AdapterSupport.result_hash(loop_device)
        loop_created = true
        dm = if @device_adapter.respond_to?(:create_dm)
               AdapterSupport.call(@device_adapter, :create_dm, device: loop_id, volume_id: id, size_bytes: size)
             else
               raise UnsupportedError, "loop-DM backend requires an injected device-mapper adapter"
             end
        dm_hash = AdapterSupport.result_hash(dm)
        dm_id = dm_hash["id"] || dm_hash["path"] || dm_hash["device"]
        raise MountIdentityError, "device-mapper adapter returned no device identity" if dm_id.to_s.empty?

        @device_source = dm_hash["path"] || dm_hash["device"] || dm_id
        @dm_id = dm_id
        @dm_identity = dm_hash
        dm_created = true
        {"source" => @device_source, "backend" => type,
         "loop" => AdapterSupport.result_hash(loop_device), "deviceMapper" => dm_hash, "capacityBytes" => size}
      rescue StandardError => error
        cleanup_loop_dm_devices!(dm_created: defined?(dm_created) && dm_created == true,
                                 loop_created: defined?(loop_created) && loop_created == true)
        raise error
      end

      def source_path
        @device_source || super
      end

      # The device carries a filesystem the operator formatted (Kubernetes
      # local/block PVs are pre-formatted as well); mount(2) needs the type
      # because a NULL fstype is only valid for bind/remount/move.
      #
      # An unset fsType defaults to ext4, exactly as upstream does in
      # SafeFormatAndMount ("Use 'ext4' as the default",
      # staging/src/k8s.io/mount-utils/mount_linux.go).  Returning nil here
      # used to make Backend#stage classify a block device as a BIND mount:
      # it bound the device inode instead of mounting its filesystem, and,
      # being a bind, it also skipped the strict superblock-identity check
      # that a persistent block mount must pass.
      DEFAULT_FILESYSTEM = "ext4"

      def filesystem
        value = Types.key(spec, "fsType", Types.key(spec, "filesystem"))
        return DEFAULT_FILESYSTEM if value.nil? || value.to_s.empty?

        text = String(value)
        raise ValidationError, "loop-DM fsType #{text.inspect} is not ext4 or xfs" unless %w[ext4 xfs].include?(text.downcase)

        text.downcase
      end

      def delete
        cleanup_loop_dm_devices!(dm_created: !@dm_id.nil?, loop_created: !@loop_id.nil?)
        true
      end

      private

      def cleanup_loop_dm_devices!(dm_created:, loop_created:)
        return true unless @device_adapter.respond_to?(:destroy_device)

        cleanup_errors = []
        # Reverse order of acquisition (R-1.3): the dm table references the
        # loop device, so the loop can only be cleared once dm is gone.  The
        # full identity hash is passed so the adapter verifies loop number,
        # backing inode and dm uuid before releasing anything.
        if dm_created && @dm_id
          begin
            AdapterSupport.call(@device_adapter, :destroy_device, id: device_identity_argument(@dm_identity, @dm_id),
                                                                  volume_id: id)
          rescue StandardError => error
            cleanup_errors << ["device-mapper", error]
          end
        end
        if loop_created && @loop_id && cleanup_errors.empty?
          begin
            AdapterSupport.call(@device_adapter, :destroy_device, id: device_identity_argument(@loop_identity, @loop_id),
                                                                  volume_id: id)
          rescue StandardError => error
            cleanup_errors << ["loop", error]
          end
        end
        return true if cleanup_errors.empty?

        kind, error = cleanup_errors.first
        raise MountIdentityError, "loop-DM cleanup failed for #{kind} device #{id}: #{error.message}", cause: error
      end

      def device_identity_argument(identity, fallback_id)
        return fallback_id unless identity.respond_to?(:to_h)

        hash = identity.to_h.transform_keys(&:to_s)
        return fallback_id if hash.empty? || !Types.present?(hash["id"] || hash["path"] || hash["device"])

        hash
      end
    end

    require_relative "static_storage_backends"

    BUILTIN_BACKENDS = {
      "emptyDir" => EmptyDirBackend, "hostPath" => HostPathBackend, "configMap" => ConfigMapBackend,
      "secret" => SecretBackend, "downwardAPI" => DownwardAPIBackend, "projected" => ProjectedBackend,
      "image" => ImageBackend, "local" => LocalBackend, "loopDM" => LoopDMBackend,
      "nfs" => NFSBackend, "iscsi" => ISCSIBackend, "fc" => FibreChannelBackend,
      "loop-DM" => LoopDMBackend, "loop-dm" => LoopDMBackend,
      "loopDevice" => LoopDMBackend, "deviceMapper" => LoopDMBackend
    }.freeze

    EmptyDir = EmptyDirBackend unless const_defined?(:EmptyDir, false)
    HostPath = HostPathBackend unless const_defined?(:HostPath, false)
    ConfigMap = ConfigMapBackend unless const_defined?(:ConfigMap, false)
    Secret = SecretBackend unless const_defined?(:Secret, false)
    DownwardAPI = DownwardAPIBackend unless const_defined?(:DownwardAPI, false)
    Projected = ProjectedBackend unless const_defined?(:Projected, false)
    Image = ImageBackend unless const_defined?(:Image, false)
    Local = LocalBackend unless const_defined?(:Local, false)
    LoopDM = LoopDMBackend unless const_defined?(:LoopDM, false)

    BuiltinBackend = Backend unless const_defined?(:BuiltinBackend, false)
  end
end
