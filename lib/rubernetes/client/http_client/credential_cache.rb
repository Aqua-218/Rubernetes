# frozen_string_literal: true

module Rubernetes
  module Client
    class HTTPClient
      private

      def static_client_certificate
        if @client_certificate_store
          certificate = key = @client_certificate_store.current_pair
        else
          certificate = context_value(:client_certificate_data)
          certificate = read_credential_file(context_value(:client_certificate_file), "client certificate") if certificate.nil?
          key = context_value(:client_key_data)
          key = read_credential_file(context_value(:client_key_file), "client key", sensitive: true) if key.nil?
        end
        return {} if certificate.nil? && key.nil?
        raise ConfigurationError, "client certificate and client key must be supplied together" if certificate.nil? || key.nil?

        tls_cache(:client_pair, [certificate, key]) do
          parsed_certificate = OpenSSL::X509::Certificate.new(certificate)
          parsed_key = OpenSSL::PKey.read(key)
          raise ConfigurationError, "client certificate does not match client private key" unless parsed_certificate.check_private_key(parsed_key)

          {cert: parsed_certificate, key: parsed_key}
        end
      end

      # Parsing an X.509 certificate and a private key, and proving they match,
      # costs real CPU -- doing it on every API request turns a control loop
      # into a key-parsing benchmark.  The result is memoised against the
      # exact bytes it was derived from, so rotated credentials are still
      # picked up the moment their content changes.
      def tls_cache(slot, material)
        @tls_cache ||= {}
        digest = Digest::SHA256.hexdigest(Array(material).join("\x00"))
        cached = @tls_cache[slot]
        return cached[:value] if cached && cached[:digest] == digest

        value = yield
        @tls_cache[slot] = {digest: digest, value: value}
        value
      end

      # Credential files are re-read only when they change on disk; the
      # symlink audit and the permission checks run on that same path.
      def read_credential_file(path, label, sensitive: false)
        return nil if path.nil?

        stat = begin
          File.stat(path)
        rescue SystemCallError
          nil
        end
        token = stat && [stat.ino, stat.size, stat.mtime.to_f, stat.mode]
        @credential_files ||= {}
        cached = @credential_files[path]
        return cached[:content] if cached && token && cached[:token] == token

        content = read_file(path, label, sensitive: sensitive)
        @credential_files[path] = {token: token, content: content} if token
        content
      end

      def read_file(path, label, sensitive: false)
        return nil if path.nil?

        reject_symlink_components(path, label)

        flags = File::RDONLY
        flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
        File.open(path, flags) do |file|
          file.binmode
          stat = file.stat
          raise ConfigurationError, "#{label} file must be a regular file: #{path}" unless stat.file?
          raise ConfigurationError, "#{label} file has no read permission: #{path}" if stat.mode.nobits?(0o444)
          raise ConfigurationError, "#{label} file must not grant permissions to group or other users: #{path}" if sensitive && stat.mode.anybits?(0o077)

          content = file.read(MAX_CREDENTIAL_FILE_BYTES + 1)
          if content.bytesize > MAX_CREDENTIAL_FILE_BYTES
            raise ConfigurationError,
                  "#{label} file exceeds #{MAX_CREDENTIAL_FILE_BYTES} bytes: #{path}"
          end
          raise ConfigurationError, "#{label} file is empty: #{path}" if content.empty?

          content
        end
      rescue ConfigurationError
        raise
      rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR, Errno::ELOOP => error
        raise ConfigurationError.new("cannot read #{label} file #{path}: #{error.message}", cause: error), cause: error
      end

      def reject_symlink_components(path, label)
        current = File::SEPARATOR
        File.expand_path(path).split(File::SEPARATOR).each do |component|
          next if component.empty?

          current = File.join(current, component)
          raise ConfigurationError, "#{label} file must not contain symlinks: #{path}" if File.symlink?(current)
        end
      end
    end
  end
end
