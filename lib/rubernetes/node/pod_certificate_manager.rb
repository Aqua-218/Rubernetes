# frozen_string_literal: true

require "base64"
require "openssl"
require "securerandom"
require "time"

module Rubernetes
  module Node
    # pkg/kubelet/podcertificate (PodCertificateRequest feature gate): for
    # every projected `podCertificate` volume source the kubelet generates a
    # key, files a PodCertificateRequest for the Pod, waits for a signer to
    # issue the chain, hands the credential bundle to the volume and files a
    # refresh request once status.beginRefreshAt passes.  The projections'
    # states are the kubelet_podcertificate_states{signer_name,state} gauge.
    class PodCertificateManager
      class Error < StandardError; end
      # The credentials are not issued (yet, or ever): the volume setup retries.
      class NotReady < Error; end

      ASSUME_DELETED_SECONDS = 10 * 60.0
      REFRESH_OVERDUE_SECONDS = 10 * 60.0
      JITTER_MAX_SECONDS = 5 * 60.0
      KEY_TYPES = %w[RSA3072 RSA4096 ECDSAP256 ECDSAP384 ECDSAP521 ED25519].freeze
      API_VERSION = "certificates.k8s.io/v1beta1"

      Key = Struct.new(:namespace, :pod_name, :pod_uid, :volume_name, :source_index, keyword_init: true)

      # One projection's credential state (credState upstream).
      class Record
        attr_accessor :state, :private_key_pem, :cert_chain_pem, :pcr_name, :pcr_abandon_at, :begin_refresh_at, :not_after,
                      :refresh_private_key_pem, :refresh_pcr_name, :refresh_pcr_abandon_at, :reason, :message,
                      :overdue_event_emitted, :expired_event_emitted, :version, :source, :pod

        def initialize(source:, pod:)
          @state = :initial
          @source = source
          @pod = pod
          @version = 0
          @overdue_event_emitted = false
          @expired_event_emitted = false
        end

        def signer_name = @source["signerName"].to_s

        # metricsState.
        def metrics_state(now)
          case @state
          when :initial, :wait then "not_yet_issued"
          when :denied then "denied"
          when :failed then "failed"
          else
            return "expired" if @not_after && now > @not_after
            return "overdue_for_refresh" if @begin_refresh_at && now > @begin_refresh_at + REFRESH_OVERDUE_SECONDS

            "fresh"
          end
        end

        def credential_bundle
          case @state
          when :fresh, :wait_refresh then [@private_key_pem, @cert_chain_pem]
          when :denied then raise NotReady, "PodCertificateRequest was permanently denied: reason=#{@reason.inspect} message=#{@message.inspect}"
          when :failed then raise NotReady, "PodCertificateRequest failed: reason=#{@reason.inspect} message=#{@message.inspect}"
          else raise NotReady, "credential bundle is not issued yet"
          end
        end
      end

      attr_reader :node_name

      # +client+: the node's API client (create / get); +node_uid+: -> uid;
      # +events+: ->(pod, type, reason, message) (optional).
      def initialize(client:, node_name:, node_uid: nil, clock: -> { Time.now.utc }, logger: nil, events: nil,
                     jitter: -> { SecureRandom.random_number * JITTER_MAX_SECONDS }, poll_interval: 1.0)
        @client = client
        @node_name = node_name.to_s
        @node_uid = node_uid
        @clock = clock
        @logger = logger
        @events = events
        @jitter = jitter
        @poll_interval = poll_interval
        @mutex = Mutex.new
        @records = {}
        @thread = nil
        @stop = false
      end

      # A projected podCertificate source of a Pod (the volume's setup).
      def register(pod, volume_name, source_index, source)
        key = key_for(pod, volume_name, source_index)
        @mutex.synchronize { @records[key] ||= Record.new(source: source, pod: pod) }
        key
      end

      def forget_pod(pod_uid)
        @mutex.synchronize { @records.delete_if { |key, _| key.pod_uid == pod_uid.to_s } }
      end

      def key_for(pod, volume_name, source_index)
        metadata = pod["metadata"] || {}
        Key.new(namespace: metadata["namespace"].to_s, pod_name: metadata["name"].to_s, pod_uid: metadata["uid"].to_s,
                volume_name: volume_name.to_s, source_index: source_index.to_i)
      end

      # [private key PEM, certificate chain PEM] or raises NotReady.  A
      # projection nobody registered yet is registered and driven once.
      def credential_bundle(pod, volume_name, source_index, source = nil)
        key = source ? register(pod, volume_name, source_index, source) : key_for(pod, volume_name, source_index)
        record = @mutex.synchronize { @records[key] }
        raise NotReady, "no credentials yet for #{key.to_h}" if record.nil?

        step(key) if record.state == :initial
        record.credential_bundle
      end

      # Changes whenever a new chain was issued (the volume rewrites its files).
      def version(pod, volume_name, source_index)
        record = @mutex.synchronize { @records[key_for(pod, volume_name, source_index)] }
        record&.version || 0
      end

      # GetMetricReport: {[signer_name, state] => count}.
      def metric_report
        now = @clock.call
        @mutex.synchronize do
          @records.values.each_with_object(Hash.new(0)) { |record, report| report[[record.signer_name, record.metrics_state(now)]] += 1 }
        end
      end

      def start
        return self if @thread&.alive?

        @stop = false
        @thread = Thread.new do
          Thread.current.name = "pod-certificates"
          until @stop
            step_all
            sleep(@poll_interval)
          end
        end
        self
      end

      def stop
        @stop = true
        thread = @thread
        @thread = nil
        thread&.join(2)
        self
      end

      def step_all
        keys = @mutex.synchronize { @records.keys }
        keys.each do |key|
          step(key)
        rescue StandardError => error
          @logger&.warn("podcertificate.step_failed", key: key.to_h, error: error.message.to_s[0, 200]) if @logger.respond_to?(:warn)
        end
      end

      # handleProjection: one turn of the state machine.
      def step(key)
        record = @mutex.synchronize { @records[key] }
        return if record.nil?

        now = @clock.call
        case record.state
        when :initial
          key_pem, pcr = create_request(record, key)
          record.private_key_pem = key_pem
          record.pcr_name = pcr.dig("metadata", "name")
          record.pcr_abandon_at = creation_time(pcr) + ASSUME_DELETED_SECONDS + @jitter.call
          record.state = :wait
        when :wait
          pcr = fetch_request(key.namespace, record.pcr_name)
          if pcr.nil?
            record.state = :initial if now > record.pcr_abandon_at
            return
          end
          settle(record, pcr, record.private_key_pem, key)
        when :fresh
          return if now < record.begin_refresh_at

          emit_lateness(record, now)
          key_pem, pcr = create_request(record, key)
          record.refresh_private_key_pem = key_pem
          record.refresh_pcr_name = pcr.dig("metadata", "name")
          record.refresh_pcr_abandon_at = creation_time(pcr) + ASSUME_DELETED_SECONDS + @jitter.call
          record.state = :wait_refresh
        when :wait_refresh
          pcr = fetch_request(key.namespace, record.refresh_pcr_name)
          if pcr.nil?
            record.state = :fresh if now > record.refresh_pcr_abandon_at
            return
          end
          settled = settle(record, pcr, record.refresh_private_key_pem, key)
          emit_lateness(record, now) unless settled
        end
      end

      # -- key material ---------------------------------------------------------

      # generateKeyAndProof: the private key and a stub PKCS#10 request
      # proving possession (empty subject, signed by the key).
      def self.generate_key_and_proof(key_type)
        key = case key_type.to_s
              when "RSA3072" then OpenSSL::PKey::RSA.new(3072)
              when "RSA4096" then OpenSSL::PKey::RSA.new(4096)
              when "ECDSAP256" then OpenSSL::PKey::EC.generate("prime256v1")
              when "ECDSAP384" then OpenSSL::PKey::EC.generate("secp384r1")
              when "ECDSAP521" then OpenSSL::PKey::EC.generate("secp521r1")
              when "ED25519" then OpenSSL::PKey.generate_key("ED25519")
              else raise Error, "unknown key type #{key_type.inspect}"
              end
        request = OpenSSL::X509::Request.new
        request.version = 0
        request.subject = OpenSSL::X509::Name.new
        request.public_key = key
        request.sign(key, key_type.to_s == "ED25519" ? nil : OpenSSL::Digest.new("SHA256"))
        [key, request.to_der]
      end

      # cleanCertificateChain: only the CERTIFICATE blocks, re-encoded.
      def self.clean_certificate_chain(pem)
        pem.to_s.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m).map do |block|
          OpenSSL::X509::Certificate.new(block).to_pem
        end.join
      rescue OpenSSL::X509::CertificateError => error
        raise Error, "while cleaning certificate chain: #{error.message}"
      end

      private

      def create_request(record, key)
        source = record.source
        pod = record.pod
        service_account = pod.dig("spec", "serviceAccountName").to_s
        service_account = "default" if service_account.empty?
        account = @client.get("serviceaccounts", service_account, namespace: key.namespace, api_version: "v1")
        raise Error, "while fetching service account: #{key.namespace}/#{service_account} not found" if account.nil?

        node_uid = @node_uid.respond_to?(:call) ? @node_uid.call : @node_uid
        private_key, stub = self.class.generate_key_and_proof(source["keyType"] || "ED25519")
        manifest = {
          "apiVersion" => API_VERSION, "kind" => "PodCertificateRequest",
          "metadata" => {"generateName" => "req-", "namespace" => key.namespace,
                         "ownerReferences" => [{"apiVersion" => "v1", "kind" => "Pod", "name" => key.pod_name, "uid" => key.pod_uid}]},
          "spec" => {"signerName" => source["signerName"], "podName" => key.pod_name, "podUID" => key.pod_uid,
                     "serviceAccountName" => service_account, "serviceAccountUID" => account.dig("metadata", "uid").to_s,
                     "nodeName" => @node_name, "nodeUID" => node_uid.to_s,
                     "stubPKCS10Request" => Base64.strict_encode64(stub)}
        }
        manifest["spec"]["maxExpirationSeconds"] = source["maxExpirationSeconds"] if source["maxExpirationSeconds"]
        manifest["spec"]["unverifiedUserAnnotations"] = source["userAnnotations"] if source["userAnnotations"].is_a?(Hash) && !source["userAnnotations"].empty?
        created = @client.create(manifest, namespace: key.namespace, api_version: API_VERSION)
        raise Error, "while creating PodCertificateRequest: empty response" unless created.is_a?(Hash)

        [private_key.private_to_pem, created]
      end

      def fetch_request(namespace, name)
        @client.get("podcertificaterequests", name, namespace: namespace, api_version: API_VERSION)
      rescue StandardError => error
        raise unless not_found?(error)

        nil
      end

      def not_found?(error)
        (error.respond_to?(:status) && error.status.to_i == 404) || (error.respond_to?(:code) && error.code.to_i == 404) || error.message.to_s.match?(/\b404\b|not found/i)
      end

      # The terminal conditions of a request: Denied / Failed end it, Issued
      # makes the record fresh.  Returns true when it settled.
      def settle(record, pcr, private_key_pem, key)
        Array(pcr.dig("status", "conditions")).each do |condition|
          case condition["type"]
          when "Denied", "Failed"
            record.state = condition["type"] == "Denied" ? :denied : :failed
            record.reason = condition["reason"].to_s
            record.message = condition["message"].to_s
            event(record.pod, "Warning", condition["type"], "PodCertificateRequest #{key.namespace}/#{pcr.dig("metadata", "name")} #{condition["type"] == "Denied" ? "was denied" : "failed"}, reason=#{record.reason.inspect}, message=#{record.message.inspect}")
            return true
          when "Issued"
            record.private_key_pem = private_key_pem
            record.cert_chain_pem = self.class.clean_certificate_chain(pcr.dig("status", "certificateChain"))
            record.begin_refresh_at = parse_time(pcr.dig("status", "beginRefreshAt")) + @jitter.call
            record.not_after = parse_time(pcr.dig("status", "notAfter"))
            record.overdue_event_emitted = false
            record.expired_event_emitted = false
            record.version += 1
            record.state = :fresh
            return true
          end
        end
        false
      end

      def emit_lateness(record, now)
        if now > record.begin_refresh_at + REFRESH_OVERDUE_SECONDS && !record.overdue_event_emitted
          event(record.pod, "Warning", "CertificateOverdueForRefresh", "PodCertificate refresh overdue")
          record.overdue_event_emitted = true
        end
        return unless record.not_after && now > record.not_after && !record.expired_event_emitted

        event(record.pod, "Warning", "CertificateExpired", "PodCertificate expired")
        record.expired_event_emitted = true
      end

      def event(pod, type, reason, message)
        @events&.call(pod, type, reason, message)
      rescue StandardError
        nil
      end

      def creation_time(pcr)
        parse_time(pcr.dig("metadata", "creationTimestamp")) || @clock.call
      end

      def parse_time(value)
        return nil if value.nil? || value.to_s.empty?

        Time.iso8601(value.to_s).utc
      rescue ArgumentError
        nil
      end
    end
  end
end
