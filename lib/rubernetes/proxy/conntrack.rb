# frozen_string_literal: true

require "digest"
require "ipaddr"

module Rubernetes
  module Proxy
    # Five-tuple connection key.  It intentionally includes the protocol so a
    # TCP and UDP flow using the same ports cannot collide.
    class ConnectionKey
      attr_reader :protocol, :source_ip, :source_port, :destination_ip, :destination_port

      def initialize(value = nil, protocol: nil, source_ip: nil, source_port: nil,
                     destination_ip: nil, destination_port: nil, **_options)
        packet = value.is_a?(Packet) ? value : nil
        @protocol = ModelSupport.normalize_protocol(protocol || packet&.protocol || ModelSupport.key(value || {}, "protocol", "TCP"))
        @source_ip = ModelSupport.canonical_ip(source_ip || packet&.source_ip || ModelSupport.key(value || {}, "sourceIP",
                                                                                                  ModelSupport.key(value || {}, "srcIP", nil)))
        @source_port = ModelSupport.integer(source_port || packet&.source_port || ModelSupport.key(value || {}, "sourcePort",
                                                                                                   ModelSupport.key(value || {}, "srcPort", nil)))
        @destination_ip = ModelSupport.canonical_ip(destination_ip || packet&.destination_ip || ModelSupport.key(value || {},
                                                                                                                 "destinationIP", ModelSupport.key(value || {},
                                                                                                                                                   "dstIP",
                                                                                                                                                   nil)))
        @destination_port = ModelSupport.integer(destination_port || packet&.destination_port || ModelSupport.key(value || {},
                                                                                                                  "destinationPort",
                                                                                                                  ModelSupport.key(value || {}, "dstPort",
                                                                                                                                   nil)))
        raise ValidationError, "connection destination IP is required" if @destination_ip.nil?
        raise ValidationError, "connection destination port must be between 1 and 65535" unless @destination_port&.between?(1, 65_535)
        raise ValidationError, "connection source port must be between 0 and 65535" if @source_port && !@source_port.between?(0, 65_535)

        freeze
      end

      def to_a
        [protocol, source_ip, source_port, destination_ip, destination_port].freeze
      end

      def to_h
        {"protocol" => protocol, "sourceIP" => source_ip, "sourcePort" => source_port,
         "destinationIP" => destination_ip, "destinationPort" => destination_port}
      end

      def hash
        to_a.hash
      end

      def eql?(other)
        other.is_a?(ConnectionKey) && to_a == other.to_a
      end

      alias == eql?
    end

    Connection = Struct.new(:key, :service_key, :backend, :created_at, :last_seen,
                            :expires_at, :affinity, :generation, keyword_init: true) do
      def initialize(**attributes)
        super
        freeze
      end

      def expired?(now)
        expires_at && now.to_f >= expires_at.to_f
      end

      def touch(now:, timeout:)
        self.class.new(key: key, service_key: service_key, backend: backend,
                       created_at: created_at, last_seen: now,
                       expires_at: timeout ? now.to_f + timeout.to_f : expires_at,
                       affinity: affinity, generation: generation)
      end
    end

    # Thread-safe conntrack and ClientIP affinity table.  Existing connections
    # keep their backend while it remains eligible; stale or removed backends
    # are replaced deterministically on the next packet. Routing affinity has
    # its own deadline and capacity, independent of individual connections.
    class ConntrackTable
      attr_reader :clock

      def initialize(clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }, max_entries: 1_000_000)
        @clock = clock
        @max_entries = Integer(max_entries)
        raise ArgumentError, "max_entries must be positive" unless @max_entries.positive?

        @mutex = Mutex.new
        @connections = {}
        @affinity = {}
        @bound_affinity_keys = {}
      end

      def fetch(key, now: @clock.call)
        normalized = normalize_key(key)
        @mutex.synchronize do
          remove_expired_locked(now)
          connection = @connections[normalized]
          return nil unless connection

          touched = connection.touch(now: now, timeout: nil)
          @connections[normalized] = touched
          touched
        end
      end

      alias lookup fetch

      def find_or_select(key, service_key:, backends:, selector:, session_affinity: "None",
                         source_ip: nil, timeout_seconds: 10_800, generation: 0, now: @clock.call)
        normalized = normalize_key(key)
        candidates = Array(backends).sort_by { |backend| backend_identity(backend) }
        raise NoRoute, "service #{service_key} has no eligible endpoints" if candidates.empty?

        timeout = Integer(timeout_seconds)
        raise ValidationError, "session affinity timeout must be positive" unless timeout.positive?

        @mutex.synchronize do
          remove_expired_locked(now)
          existing = @connections[normalized]
          if existing && candidates.any? { |candidate| backend_identity(candidate) == backend_identity(existing.backend) }
            touched = existing.touch(now: now, timeout: nil)
            @connections[normalized] = touched
            return touched
          end
          backend = affinity_backend_locked(service_key, source_ip, candidates, session_affinity, now)
          backend ||= selector.call(candidates)
          raise NoRoute, "selector returned no backend for #{service_key}" if backend.nil?

          remove_connection_locked(normalized) if existing
          ensure_capacity_locked
          connection = Connection.new(key: normalized, service_key: service_key.to_s, backend: backend,
                                      created_at: now, last_seen: now,
                                      affinity: session_affinity.to_s == "ClientIP", generation: generation)
          @connections[normalized] = connection
          store_affinity_locked(service_key, source_ip, connection.touch(now: now, timeout: timeout)) if connection.affinity && source_ip
          connection
        end
      end

      alias route find_or_select

      def bind(key, service_key:, backend:, affinity: false, source_ip: nil, timeout_seconds: nil,
               generation: 0, now: @clock.call)
        normalized = normalize_key(key)
        @mutex.synchronize do
          remove_expired_locked(now)
          remove_connection_locked(normalized)
          ensure_capacity_locked
          connection = Connection.new(key: normalized, service_key: service_key.to_s, backend: backend,
                                      created_at: now, last_seen: now,
                                      expires_at: timeout_seconds ? now.to_f + timeout_seconds.to_f : nil,
                                      affinity: !!affinity, generation: generation)
          @connections[normalized] = connection
          store_affinity_locked(service_key, source_ip, connection, bound: true) if affinity && source_ip
          connection
        end
      end

      def delete(key)
        normalized = normalize_key(key)
        @mutex.synchronize { remove_connection_locked(normalized) }
      end

      def remove_backend(backend_or_identity)
        identity = backend_identity(backend_or_identity)
        @mutex.synchronize do
          removed = @connections.filter_map do |key, connection|
            next unless backend_identity(connection.backend) == identity

            @connections.delete(key)
          end
          discard_affinities_locked { |connection| backend_identity(connection.backend) == identity }
          removed.freeze
        end
      end

      def clear(service_key: nil)
        @mutex.synchronize do
          if service_key
            service = service_key.to_s
            @connections.delete_if { |_key, connection| connection.service_key == service }
            discard_affinities_locked { |connection| connection.service_key == service }
          else
            @connections.clear
            @affinity.clear
            @bound_affinity_keys.clear
          end
        end
        self
      end

      def size
        @mutex.synchronize { @connections.size }
      end

      def connections
        @mutex.synchronize { @connections.values.dup.freeze }
      end

      def affinity_for(service_key, source_ip, now: @clock.call)
        @mutex.synchronize { active_affinity_locked(service_key, source_ip, now) }
      end

      def prune(now: @clock.call)
        @mutex.synchronize do
          expired = remove_expired_locked(now)
          discard_affinities_locked { |connection| connection.expired?(now) }
          expired
        end
      end

      private

      def normalize_key(key)
        return key if key.is_a?(ConnectionKey)

        ConnectionKey.new(key)
      end

      def backend_identity(backend)
        return backend.identity.to_s if backend.respond_to?(:identity)
        return backend.id.to_s if backend.respond_to?(:id)

        backend.to_s
      end

      def affinity_backend_locked(service_key, source_ip, candidates, affinity, now)
        return nil unless affinity.to_s == "ClientIP" && source_ip

        current = active_affinity_locked(service_key, source_ip, now)
        return nil unless current

        candidates.find { |candidate| backend_identity(candidate) == backend_identity(current.backend) }
      end

      def active_affinity_locked(service_key, source_ip, now)
        key = [service_key.to_s, source_ip.to_s]
        lease = @affinity[key]
        return lease unless lease&.expired?(now)

        delete_affinity_locked(key)
        nil
      end

      def store_affinity_locked(service_key, source_ip, connection, bound: false)
        key = [service_key.to_s, source_ip.to_s]
        # Reinsert at the end of the ordered hash on new-flow use.
        delete_affinity_locked(key)
        if @affinity.size >= @max_entries
          discard_affinities_locked { |lease| lease.expired?(connection.last_seen) }
          delete_affinity_locked(@affinity.each_key.first) if @affinity.size >= @max_entries
        end
        @affinity[key] = connection
        @bound_affinity_keys[connection.key] = key if bound
      end

      def ensure_capacity_locked
        return if @connections.size < @max_entries

        oldest_key, = @connections.min_by { |_key, connection| connection.last_seen.to_f }
        remove_connection_locked(oldest_key)
      end

      def remove_expired_locked(now)
        expired = @connections.filter_map do |key, connection|
          next unless connection.expired?(now)

          remove_connection_locked(key)
        end
        expired.freeze
      end

      def remove_connection_locked(key)
        # Explicit bind may attach affinity to its connection. A lease
        # learned from routing remains valid when that flow disappears.
        affinity_key = @bound_affinity_keys.delete(key)
        @affinity.delete(affinity_key) if affinity_key
        @connections.delete(key)
      end

      def delete_affinity_locked(key)
        lease = @affinity.delete(key)
        @bound_affinity_keys.delete(lease.key) if lease && @bound_affinity_keys[lease.key] == key
      end

      def discard_affinities_locked
        @affinity.each do |key, lease|
          delete_affinity_locked(key) if yield lease
        end
      end
    end

    # Jenkins lookup3 over the source address. A fresh ClientIP selection
    # also hashes the source port and scales the result like nftables.
    class DeterministicHash
      MASK32 = 0xffff_ffff

      def initialize(seed: "rubernetes-proxy-v1")
        # The argument remains accepted for API compatibility, but packet
        # selection is intentionally seed-zero so both kernel backends share
        # one immutable contract.
        @seed = seed.to_s.freeze
      end

      def score(key, backend)
        [packet_hash(key), backend_identity(backend)].hash
      end

      def select(key, backends, client_ip_affinity: false)
        candidates = Array(backends).sort_by { |backend| backend_identity(backend) }
        return nil if candidates.empty?

        hash = client_ip_affinity ? self.class.packet_hash(key, include_source_port: true) : packet_hash(key)
        index = client_ip_affinity ? (hash * candidates.length) >> 32 : hash % candidates.length
        candidates.fetch(index)
      end

      alias call select

      def packet_hash(key)
        self.class.packet_hash(key)
      end

      def self.packet_hash(key, include_source_port: false)
        fields = key.respond_to?(:to_a) ? key.to_a : key.to_s.split("|", 5)
        source_ip = fields[1].to_s
        bytes = if source_ip.empty?
                  "".b
                else
                  IPAddr.new(source_ip).hton
                end
        bytes += [fields[2].to_i].pack("nxx") if include_source_port
        jenkins_hash(bytes)
      rescue ArgumentError
        0
      end

      JHASH_INITVAL = 0xdeadbeef

      # Linux jhash() (Bob Jenkins' lookup3 hashlittle) over raw bytes with
      # little-endian word loads: the exact function nftables applies with
      # NFT_HASH_JENKINS, so a flow hashes to the same backend on every
      # kernel datapath and survives a backend switch.
      def self.jenkins_hash(bytes, seed: 0)
        data = String(bytes).b
        length = data.bytesize
        a = b = c = (JHASH_INITVAL + length + (Integer(seed) & MASK32)) & MASK32
        offset = 0
        while length - offset > 12
          a = (a + data.byteslice(offset, 4).unpack1("L<")) & MASK32
          b = (b + data.byteslice(offset + 4, 4).unpack1("L<")) & MASK32
          c = (c + data.byteslice(offset + 8, 4).unpack1("L<")) & MASK32
          a, b, c = jhash_mix(a, b, c)
          offset += 12
        end
        tail = data.byteslice(offset, length - offset).to_s.ljust(12, "\0").unpack("L<L<L<")
        remaining = length - offset
        return c if remaining.zero?

        a = (a + tail[0]) & MASK32
        b = (b + tail[1]) & MASK32 if remaining > 4
        c = (c + tail[2]) & MASK32 if remaining > 8
        jhash_final(a, b, c)
      end

      def self.rol32(value, bits)
        ((value << bits) | (value >> (32 - bits))) & MASK32
      end

      def self.jhash_mix(a, b, c)
        a = (a - c) & MASK32
        a ^= rol32(c, 4)
        c = (c + b) & MASK32
        b = (b - a) & MASK32
        b ^= rol32(a, 6)
        a = (a + c) & MASK32
        c = (c - b) & MASK32
        c ^= rol32(b, 8)
        b = (b + a) & MASK32
        a = (a - c) & MASK32
        a ^= rol32(c, 16)
        c = (c + b) & MASK32
        b = (b - a) & MASK32
        b ^= rol32(a, 19)
        a = (a + c) & MASK32
        c = (c - b) & MASK32
        c ^= rol32(b, 4)
        b = (b + a) & MASK32
        [a, b, c]
      end

      def self.jhash_final(a, b, c)
        c ^= b
        c = (c - rol32(b, 14)) & MASK32
        a ^= c
        a = (a - rol32(c, 11)) & MASK32
        b ^= a
        b = (b - rol32(a, 25)) & MASK32
        c ^= b
        c = (c - rol32(b, 16)) & MASK32
        a ^= c
        a = (a - rol32(c, 4)) & MASK32
        b ^= a
        b = (b - rol32(a, 14)) & MASK32
        c ^= b
        (c - rol32(b, 24)) & MASK32
      end

      private

      def canonical_key(key)
        key.respond_to?(:to_a) ? key.to_a.join("|") : key.to_s
      end

      def backend_identity(backend)
        return backend.identity.to_s if backend.respond_to?(:identity)

        backend.to_s
      end
    end

    RendezvousHash = DeterministicHash
    ConsistentHasher = DeterministicHash
    DeterministicHasher = DeterministicHash
    AffinityTable = ConntrackTable
  end
end
