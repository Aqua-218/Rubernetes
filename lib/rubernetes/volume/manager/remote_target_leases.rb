# frozen_string_literal: true

# The descriptor leases RemoteBackend holds on a CSI target while a plugin acts
# on it: acquire the target through openat2, run the RPC, then prove that the
# visible path and its mount still name the pinned inode -- fencing the
# operation (and compensating a mount) when they do not.
module Rubernetes
  module Volume
    class RemoteBackend < Backend
      module TargetLeases
        private

        def with_secure_csi_target(path, directory:, create:, post_effect: :unchanged, compensation: nil)
          ensure_descriptor_target_security!
          mounted = mounted_post_effect?(post_effect)
          lease = @path_security.acquire_target!(path, directory: directory, create: create)
          result = nil
          primary_error = nil
          begin
            # CSI plugins receive the canonical pathname, exactly as kubelet
            # sends it.  A /proc/<pid>/fd/<n> alias breaks real drivers: the
            # mount-utils IsLikelyNotMountPoint heuristic compares st_dev of the
            # path and its parent, and /proc's device differs from every target,
            # so the plugin concludes "already mounted" and never mounts.  The
            # lease still pins the parent and leaf inodes; the post-effect
            # verification below binds the visible path and mountinfo entry to
            # those inodes and fences (OperationUnknown + compensation) when a
            # concurrent rename or symlink swap redirected the plugin.
            result = yield(lease.original_path, lease)
          rescue StandardError => error
            primary_error = error
          end

          verification_error = post_effect_verification_error(lease, path, result, mounted: mounted)
          compensation_error = compensation_error_for(compensation, lease, primary_error, verification_error)
          close_error = lease_close_error(lease)
          verification_error ||= close_error

          raise_unverified_target!(path, lease, primary_error, verification_error, compensation_error)
          raise primary_error if primary_error

          result
        end

        def post_effect_verification_error(lease, path, result, mounted:)
          observation = mounted ? mount_identity_for_target(path, result) : nil
          verify_target_lease!(lease, mounted: mounted, mount_identity: observation)
          nil
        rescue StandardError => error
          error
        end

        # Undoes the plugin's mount after a failed or unverifiable effect,
        # unless the primary failure is itself ambiguous.  Returns the error
        # the compensation raised, if any.
        def compensation_error_for(compensation, lease, primary_error, verification_error)
          return nil unless compensation && (primary_error || verification_error) && !ambiguous_remote_error?(primary_error)

          # Compensation must name the path the plugin acted on; the
          # descriptor alias is kept in the error details for operators.
          compensation.call(lease.original_path, lease.original_path)
          nil
        rescue StandardError => error
          error
        end

        def lease_close_error(lease)
          lease.close
          nil
        rescue StandardError => error
          error
        end

        def raise_unverified_target!(path, lease, primary_error, verification_error, compensation_error)
          if compensation_error
            primary = verification_error || primary_error
            details = {
              "primaryError" => {"class" => primary.class.name, "message" => primary.message.to_s},
              "cleanupErrors" => [{"class" => compensation_error.class.name, "message" => compensation_error.message.to_s}]
            }.merge(lease_error_details(lease))
            raise CleanupError.new(
              "CSI target compensation is ambiguous for #{path.inspect}: #{compensation_error.message}",
              details: details, cleanup_errors: [compensation_error]
            ), cause: primary
          end
          return unless verification_error

          raise OperationUnknown.new(
            "CSI target identity could not be verified: #{sanitize_error(verification_error).message}",
            details: lease_error_details(lease)
          ), cause: verification_error
        end

        def lease_error_details(lease)
          {
            "leaseIdentity" => Types.deep_copy(lease.identity),
            "originalPath" => lease.original_path,
            "dispatchPath" => lease.dispatch_path
          }
        end

        def ensure_descriptor_target_security!
          return true if @path_security && @path_security.descriptor_capable?

          raise PathSecurityError, "CSI target dispatch requires an openat2 descriptor lease"
        end

        def with_target_leases(paths, post_effect: :unchanged)
          ensure_descriptor_target_security!
          mounted_post_effect?(post_effect)
          leases = []
          begin
            Array(paths).each do |path|
              leases << [path, @path_security.acquire_target!(path, directory: nil, create: false)]
            end
            yield leases
          ensure
            verify_and_close_target_leases(leases.map(&:last), post_effect: post_effect,
                                                               mount_observer: ->(target) { mount_identity_for_target(target) })
          end
        end

        def verify_target_leases!(leases, post_effect: :unchanged)
          mounted = mounted_post_effect?(post_effect)
          Array(leases).each do |path, lease|
            observation = mounted ? mount_identity_for_target(path) : nil
            verify_target_lease!(lease, mounted: mounted, mount_identity: observation)
          end
          true
        rescue StandardError => error
          raise OperationUnknown.new("CSI target identity could not be verified: #{sanitize_error(error).message}"), cause: error
        end

        def verify_and_close_target_leases(leases, post_effect: :unchanged, mount_identity: nil, mount_observer: nil)
          mounted = mounted_post_effect?(post_effect)
          verification_error = nil
          Array(leases).each do |lease|
            observation = mount_identity || (mount_observer && mount_observer.call(lease.original_path))
            verify_target_lease!(lease, mounted: mounted, mount_identity: observation)
          rescue StandardError => error
            verification_error ||= error
          end
          Array(leases).reverse_each(&:close)
          return true unless verification_error

          raise OperationUnknown.new("CSI target identity could not be verified: #{sanitize_error(verification_error).message}"),
                cause: verification_error
        end

        # Leases only ever come from PathSecurity#acquire_target!, so the
        # verifier is PathSecurity::TargetLease#verify_original!.
        def verify_target_lease!(lease, mounted:, mount_identity: nil)
          return true unless lease

          lease.verify_original!(mounted: mounted, mount_identity: mount_identity)
        end

        def mounted_post_effect?(post_effect)
          mode = post_effect.to_sym
          return true if mode == :mounted
          return false if %i[unchanged removed].include?(mode)

          raise ValidationError, "unsupported CSI target post-effect verification mode #{post_effect.inspect}"
        rescue NoMethodError
          raise ValidationError, "CSI target post-effect verification mode must be a symbol"
        end
      end
    end
  end
end
