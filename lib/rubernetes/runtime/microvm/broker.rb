# frozen_string_literal: true

require "ipaddr"
require "json"
require "net/http"
require "resolv"
require "socket"
require "time"
require "uri"

require_relative "errors"
require_relative "framing"
require_relative "vsock_client"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # Restricted broker (spec/node/runtime.md 5.8.13): the only external
      # effect path of rubernetes-firecracker-restricted VMs.  The set of
      # operations is closed and registered here with their parameter
      # schema; every call is re-authorized at the effect point against the
      # capability bound to the calling VM (resolved from the vsock
      # connection, never from the payload): subject, object, parameters,
      # expiry, revocation epoch and policy digest.  DNS answers are
      # accepted only when every address satisfies the policy; HTTP
      # redirects are re-resolved and re-authorized hop by hop.  Unknown
      # operations and unknown fields fail closed.
      class Broker
        MAX_RESPONSE_BYTES = 1024 * 1024
        MAX_REDIRECTS = 5
        OPERATIONS = {
          "dns.resolve" => {"fields" => %w[name], "required" => %w[name]},
          "http.get" => {"fields" => %w[url headers], "required" => %w[url]},
          "time.now" => {"fields" => [], "required" => []}
        }.freeze

        Capability = Struct.new(:id, :subject_id, :vm_id, :policy_digest, :revocation_epoch, :expires_at, :operations, :allowed_hosts, :allowed_cidrs, :allowed_ports,
                                keyword_init: true) do
          def to_h
            {"id" => id, "subject_id" => subject_id, "vm_id" => vm_id, "policy_digest" => policy_digest, "revocation_epoch" => revocation_epoch,
             "expires_at" => expires_at, "operations" => operations, "allowed_hosts" => allowed_hosts, "allowed_cidrs" => allowed_cidrs, "allowed_ports" => allowed_ports}
          end
        end

        Decision = Struct.new(:allowed, :reason, keyword_init: true)

        def initialize(clock: -> { Time.now.utc }, resolver: nil, http_factory: nil, audit: nil, revocation_epoch: -> { 0 })
          @clock = clock
          @resolver = resolver || Resolv::DNS.new
          @http_factory = http_factory
          @audit = audit
          @revocation_epoch = revocation_epoch
          @capabilities = {}
          @mutex = Mutex.new
        end

        # Binds a capability to a VM identity (called when the identity is injected).
        def bind(vm_id:, identity:, policy:)
          capability = Capability.new(
            id: identity.fetch("capability_id"), subject_id: identity.fetch("subject_id"), vm_id: vm_id,
            policy_digest: identity.fetch("policy_digest"), revocation_epoch: identity.fetch("revocation_epoch"),
            expires_at: policy["expires_at"], operations: Array(policy["operations"]).map(&:to_s),
            allowed_hosts: Array(policy["allowed_hosts"]).map(&:to_s), allowed_cidrs: Array(policy["allowed_cidrs"]).map do |cidr|
                                                                         IPAddr.new(cidr)
                                                                       end,
            allowed_ports: Array(policy["allowed_ports"]).map(&:to_i)
          )
          @mutex.synchronize { @capabilities[vm_id] = capability }
          capability
        end

        def unbind(vm_id)
          @mutex.synchronize { @capabilities.delete(vm_id) }
        end

        def capability(vm_id)
          @mutex.synchronize { @capabilities[vm_id] }
        end

        # Serves guest-initiated broker connections for one VM: the caller
        # identity is the VM whose vsock backend the listener belongs to.
        def serve(listener, vm_id)
          loop do
            connection = listener.accept
            Thread.new(connection) do |io|
              Server.new(io, ->(name, params) { handle(vm_id, name, params) }).serve
            rescue StandardError
              nil
            ensure
              io.close unless io.closed?
            end
          end
        rescue IOError, SystemCallError
          nil
        end

        def handle(vm_id, name, params)
          raise ProtocolError, "unknown broker request #{name}" unless name == "broker.request"

          operation = params["operation"].to_s
          request_params = params["params"].is_a?(Hash) ? params["params"] : {}
          result = authorize_and_execute(vm_id, operation, request_params, claimed: params)
          audit(vm_id, operation, request_params, "allowed", nil)
          result
        rescue PolicyError => error
          audit(vm_id, operation, params["params"], "denied", error.message)
          raise
        end

        def authorize_and_execute(vm_id, operation, params, claimed: {})
          capability = capability(vm_id)
          raise PolicyError, "no capability bound to #{vm_id}" if capability.nil?

          authorize!(capability, operation, params, claimed)
          case operation
          when "dns.resolve" then resolve(capability, params.fetch("name"))
          when "http.get" then http_get(capability, params.fetch("url"), params["headers"] || {})
          when "time.now" then {"now" => @clock.call.iso8601(6)}
          end
        end

        # Every check happens here, at the effect point, on every call.
        def authorize!(capability, operation, params, claimed)
          schema = OPERATIONS[operation]
          raise PolicyError, "operation #{operation.inspect} is not registered" if schema.nil?

          unknown = params.keys - schema["fields"]
          raise PolicyError, "unknown fields #{unknown.join(", ")} for #{operation}" unless unknown.empty?

          missing = schema["required"] - params.keys
          raise PolicyError, "missing fields #{missing.join(", ")} for #{operation}" unless missing.empty?
          raise PolicyError, "capability #{capability.id} does not permit #{operation}" unless capability.operations.include?(operation)
          if capability.expires_at && Time.iso8601(capability.expires_at) <= @clock.call
            raise PolicyError,
                  "capability #{capability.id} expired"
          end
          if capability.revocation_epoch < @revocation_epoch.call
            raise PolicyError,
                  "capability #{capability.id} revoked (epoch #{capability.revocation_epoch} < #{@revocation_epoch.call})"
          end

          # Claims in the payload are compared, never trusted.
          %w[subject_id capability_id policy_digest].each do |field|
            next unless claimed.key?(field)

            expected = field == "capability_id" ? capability.id : capability.public_send(field)
            raise PolicyError, "claimed #{field} does not match the connection identity" unless claimed[field] == expected
          end
          return unless claimed.key?("revocation_epoch") && claimed["revocation_epoch"] != capability.revocation_epoch

          raise PolicyError,
                "claimed revocation epoch does not match"
        end

        def resolve(capability, name)
          raise PolicyError, "host #{name} is not allowed" unless host_allowed?(capability, name)

          addresses = @resolver.getaddresses(name).map(&:to_s)
          raise PolicyError, "no address for #{name}" if addresses.empty?

          rejected = addresses.reject { |address| address_allowed?(capability, address) }
          raise PolicyError, "answer for #{name} contains addresses outside the policy: #{rejected.join(", ")}" unless rejected.empty?

          {"name" => name, "addresses" => addresses}
        end

        def http_get(capability, url, headers)
          hops = 0
          current = URI.parse(url)
          loop do
            raise PolicyError, "scheme #{current.scheme} is not allowed" unless %w[http https].include?(current.scheme)
            unless capability.allowed_ports.empty? || capability.allowed_ports.include?(current.port)
              raise PolicyError,
                    "port #{current.port} is not allowed"
            end

            resolved = resolve(capability, current.host)
            address = resolved["addresses"].first
            response = perform_get(current, address, headers)
            if response.is_a?(Net::HTTPRedirection) && response["location"]
              hops += 1
              raise PolicyError, "too many redirects" if hops > MAX_REDIRECTS

              current = URI.join(current.to_s, response["location"])
              next
            end
            body = response.body.to_s
            raise PolicyError, "response exceeds #{MAX_RESPONSE_BYTES} bytes" if body.bytesize > MAX_RESPONSE_BYTES

            return {"status" => response.code.to_i, "url" => current.to_s, "address" => address, "hops" => hops,
                    "headers" => response.to_hash.transform_values(&:first).slice("content-type", "content-length", "location"), "body" => body}
          end
        end

        private

        def perform_get(uri, address, headers)
          return @http_factory.call(uri, address, headers) if @http_factory

          http = Net::HTTP.new(address, uri.port, nil)
          http.use_ssl = uri.scheme == "https"
          http.open_timeout = 5
          http.read_timeout = 10
          request = Net::HTTP::Get.new(uri.request_uri)
          request["Host"] = uri.host
          headers.each { |key, value| request[key.to_s] = value.to_s }
          http.request(request)
        rescue SystemCallError, IOError, Net::OpenTimeout, Net::ReadTimeout, OpenSSL::SSL::SSLError => error
          raise PolicyError, "request to #{uri.host} failed: #{error.class}"
        end

        def host_allowed?(capability, host)
          capability.allowed_hosts.any? do |pattern|
            pattern == host || (pattern.start_with?("*.") && host.end_with?(pattern[1..]) && host.count(".") >= pattern.count("."))
          end
        end

        def address_allowed?(capability, address)
          ip = IPAddr.new(address)
          return false if capability.allowed_cidrs.empty?

          capability.allowed_cidrs.any? { |cidr| cidr.include?(ip) }
        rescue IPAddr::InvalidAddressError
          false
        end

        def audit(vm_id, operation, params, outcome, reason)
          @audit&.call({"at" => @clock.call.iso8601(6), "vm_id" => vm_id, "operation" => operation, "params" => params,
                        "outcome" => outcome, "reason" => reason})
        end
      end
    end
  end
end
