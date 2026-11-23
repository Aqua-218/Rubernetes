# frozen_string_literal: true

module Rubernetes
  module Image
    # A stage can outlive its creating process. A PID in the name is local to
    # the creator's namespace, while a flock on the shared filesystem works
    # across PID namespaces.
    module StagingLease
      STAGE_NAME = /\Arubernetes-image-\d{8}-\d+-[A-Za-z0-9_]+\z/
      LOCK_NAME = ".lease"

      module_function

      def runtime_roots(ledger)
        Array(ledger&.resources).flat_map { |resource| Array(resource.dig(:metadata, "lowerdirs")) }
      end

      def acquire(stage)
        temporary = File.join(stage, ".lease-new")
        lock = File.open(temporary, File::RDWR | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600)
        lock.flock(File::LOCK_EX)
        # Publish only once held, so the janitor cannot race initialization.
        File.rename(temporary, File.join(stage, LOCK_NAME))
        lock
      rescue SystemCallError
        lock&.close
        raise
      end

      def reclaim(parent, protected_roots:)
        protected = protected_roots.filter_map do |root|
          path = File.expand_path(root).delete_prefix("#{parent}/")
          path.split("/", 2).first unless path.start_with?("/")
        end.to_set
        Dir.children(parent).count do |name|
          STAGE_NAME.match?(name) && !protected.include?(name) && remove_abandoned(parent, name)
        end
      rescue Errno::ENOENT
        0
      end

      def remove_abandoned(parent, name)
        stage = File.join(parent, name)
        stat = File.lstat(stage)
        return false unless stat.directory?

        marker = File.join(stage, LOCK_NAME)
        File.open(marker, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |lock|
          return false unless lock.stat.file? && lock.flock(File::LOCK_EX | File::LOCK_NB)

          held = lock.stat
          named = File.lstat(marker)
          return false unless held.dev == named.dev && held.ino == named.ino

          filesystem = ::Rubernetes::Platform::Linux::SecureRootfs.new(root: parent)
          begin
            filesystem.remove(name, expected_identity: [stat.dev, stat.ino, stat.mode], last_child: LOCK_NAME)
          ensure
            filesystem.close
          end
        end
        true
      rescue SystemCallError, ::Rubernetes::Platform::Linux::SecureRootfs::Error
        false
      end
    end
  end
end
