# frozen_string_literal: true

require "openssl"

module Rubernetes
  module Node
    # The static serving key pair and the client CA have independent
    # lifecycles. An incomplete write leaves the last installed material live.
    class KubeletTLSFiles
      POLL_INTERVAL = 0.25

      def self.certificates(path)
        certificates = OpenSSL::X509::Certificate.load(File.binread(path))
        raise ArgumentError, "certificate bundle is empty" if certificates.empty?

        certificates
      end

      def initialize(serving:, client_ca:, install:, logger:)
        @serving = serving
        @client_ca = client_ca
        @install = install
        @logger = logger
        @versions = {}
        @errors = {}
        @mutex = Mutex.new
        @condition = ConditionVariable.new
        @stopped = false
      end

      def start
        @thread = Thread.new do
          loop do
            poll
            break if @mutex.synchronize do
              @condition.wait(@mutex, POLL_INTERVAL) unless @stopped
              @stopped
            end
          end
        end
      end

      def stop
        @mutex.synchronize do
          @stopped = true
          @condition.broadcast
        end
        @thread&.join
      end

      private

      def poll
        if @serving
          reload(:serving, @serving) do |cert_file, key_file|
            certificate, *chain = self.class.certificates(cert_file)
            key = OpenSSL::PKey.read(File.binread(key_file))
            raise ArgumentError, "serving certificate and key do not match" unless certificate.check_private_key(key)

            {certificate: certificate, private_key: key, certificate_chain: chain}
          end
        end
        reload(:client_ca, [@client_ca]) { |file| {client_ca_certificates: self.class.certificates(file)} } if @client_ca
      end

      def reload(kind, paths)
        version = file_version(paths)
        return if version == @versions[kind]

        material = yield(*paths)
        # The cert and key can be replaced separately. Only publish a stable
        # read of the set, even if another replacement starts during parsing.
        return unless file_version(paths) == version

        @install.call(**material)
        @versions[kind] = version
        @errors.delete(kind)
      rescue StandardError => error
        failure = [version, error.class, error.message]
        return if @errors[kind] == failure

        @errors[kind] = failure
        @logger.call(:warn, "kubelet.tls_file_reload_failed", material: kind, error: error.message)
      end

      def file_version(paths)
        paths.map do |path|
          status = File.stat(path)
          raise ArgumentError, "certificate input must be a regular file" unless status.file?

          [status.dev, status.ino, status.size, status.mtime, status.ctime]
        end
      end
    end
  end
end
