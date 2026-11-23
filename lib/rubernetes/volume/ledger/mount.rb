# frozen_string_literal: true

module Rubernetes
  module Volume
    class MountIdentityLedger
      Mount = Struct.new(:volume_id, :source, :target, :mount_id, :filesystem_uuid, :device_id,
                         :owner, :stage_path, :generation, :secret, :root, :source_identity,
                         :filesystem_uuid_available, :filesystem, :identity_version, :legacy, :bind, :shared_source,
                         keyword_init: true) do
        def identity_fields
          {"mountId" => mount_id, "filesystemUuid" => filesystem_uuid, "deviceId" => device_id,
           "target" => target, "root" => root, "sourceIdentity" => source_identity,
           "filesystemUuidAvailable" => filesystem_uuid_available}
        end

        # The digest is recomputed only when an identity field changed: the
        # ledger compares every record's identity on each registration, and
        # re-deriving a canonical-JSON SHA-256 per record per call made
        # registering the n-th mount O(n) digests -- a quarter of a node
        # agent's CPU while a few hundred volumes were mounted.
        def fingerprint
          fields = identity_fields
          return @fingerprint if @fingerprint && @fingerprint_fields == fields

          @fingerprint_fields = fields
          @fingerprint = MountIdentityLedger.identity_fingerprint(fields)
        end

        def legacy_identity
          [mount_id, filesystem_uuid, device_id, target].join("/")
        end

        def identity
          legacy? ? legacy_identity : fingerprint
        end

        def legacy?
          legacy == true || identity_version.to_i < MountIdentityLedger::IDENTITY_VERSION
        end

        def bind?
          bind == true
        end

        def to_h
          {"volumeId" => volume_id, "source" => source, "target" => target, "mountId" => mount_id,
           "filesystemUuid" => filesystem_uuid, "filesystemUuidAvailable" => filesystem_uuid_available,
           "deviceId" => device_id, "root" => root, "sourceIdentity" => source_identity,
           "filesystem" => filesystem, "owner" => owner, "stagePath" => stage_path,
           "generation" => generation, "secret" => secret == true, "identityVersion" => identity_version,
           "bind" => bind == true}.merge(shared_source ? {"sharedSource" => shared_source} : {})
        end
      end

      def self.identity_fingerprint(fields)
        Types.digest(fields)
      end
    end
  end
end
