# frozen_string_literal: true

module Rubernetes
  module Network
    class IPAM
      Lease = Struct.new(:family, :ip, :pod_uid, :sandbox_id, :operation_id,
                         :state, :node, :subnet, :generation, :metadata,
                         keyword_init: true) do
        def [](key)
          to_h.fetch(key.to_s) { to_h.fetch(key.to_sym) }
        end

        def to_h
          {
            "family" => family,
            "ip" => ip,
            "pod_uid" => pod_uid,
            "sandbox_id" => sandbox_id,
            "operation_id" => operation_id,
            "state" => state,
            "node" => node,
            "subnet" => subnet,
            "generation" => generation,
            "metadata" => metadata || {}
          }
        end

        alias_method :address, :ip

        def committed?
          state == "committed"
        end

        def released?
          state == "released"
        end

        def reserved?
          state == "reserved"
        end
      end

      # Array-compatible return value for dual-stack reservations.  Delegating
      # the single-family fields keeps the common `lease.ip` call ergonomic
      # while retaining an explicit collection for atomic dual-stack work.
      class LeaseSet < Array
        attr_reader :operation_id, :sandbox_id, :pod_uid

        def initialize(leases, operation_id:, sandbox_id:, pod_uid:)
          super(leases)
          @operation_id = operation_id
          @sandbox_id = sandbox_id
          @pod_uid = pod_uid
          freeze
        end

        def lease
          first if length == 1
        end

        def ip
          return lease.ip if lease

          map(&:ip)
        end

        def family
          return lease.family if lease

          map(&:family)
        end

        def state
          return lease.state if lease

          map(&:state).uniq
        end

        def [](key, *rest)
          return super unless key.is_a?(String) || key.is_a?(Symbol)

          to_h.fetch(key.to_s) { to_h.fetch(key.to_sym) }
        end

        def to_h
          {
            "leases" => map(&:to_h),
            "ips" => map(&:ip),
            "families" => map(&:family),
            "operation_id" => operation_id,
            "sandbox_id" => sandbox_id,
            "pod_uid" => pod_uid,
            "state" => state
          }
        end

        def to_a
          map(&:to_h)
        end
      end

      RecoveryReport = Struct.new(:reclaimed, :unknown, :identity_mismatch,
                                  :orphans, :errors, :audit, keyword_init: true) do
        def to_h
          {
            "reclaimed" => reclaimed,
            "unknown" => unknown,
            "identity_mismatch" => identity_mismatch,
            "orphans" => orphans,
            "errors" => errors,
            "audit" => audit
          }
        end

        alias_method :released, :reclaimed
      end
    end
  end
end
