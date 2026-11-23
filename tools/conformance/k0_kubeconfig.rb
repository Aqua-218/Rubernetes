# frozen_string_literal: true

require "base64"
require "digest"
require "ipaddr"
require "openssl"
require "uri"
require "yaml"

module Conformance
  module K0
    # Compare configured endpoints and credential contents without contacting
    # either cluster or executing credential plugins.
    module Kubeconfigs
      class Invalid < StandardError; end

      class Configuration
        attr_reader :clusters, :servers, :credentials, :dynamic_credentials, :cluster_id

        def initialize(path, role)
          raise Invalid, "no #{role} kubeconfig given" if path.to_s.empty?

          @location = File.expand_path(path)
          document = YAML.safe_load(read_file(@location, "#{role} kubeconfig"), aliases: true)
          raise Invalid, "#{role} kubeconfig is not a mapping" unless document.is_a?(Hash)

          @clusters = entries(document, "clusters", "cluster")
          users = entries(document, "users", "user")
          contexts = entries(document, "contexts", "context")
          active = contexts[document["current-context"]]
          raise Invalid, "#{role} kubeconfig does not select a context" unless active

          contexts.each_value do |context|
            raise Invalid, "#{role} context names an unknown cluster" unless @clusters.key?(context["cluster"])
            raise Invalid, "#{role} context names an unknown user" if context["user"] && !users.key?(context["user"])
          end
          @servers = @clusters.transform_values { |cluster| endpoint(cluster["server"]) }
          @credentials = users.values.flat_map { |user| credential_material(user) }.uniq
          @dynamic_credentials = users.values.any? { |user| user.key?("exec") || user.key?("auth-provider") }
          cluster = @clusters.fetch(active.fetch("cluster"))
          authority = credential_bytes(cluster, "certificate-authority")
          # This is the configured endpoint identity. A K0 check does not read
          # the cluster's objects or claim that distinct DNS names are distinct clusters.
          seed = [@servers.fetch(active.fetch("cluster")), authority && Digest::SHA256.hexdigest(authority)]
          @cluster_id = "sha256:#{Digest::SHA256.hexdigest(seed.join("\n"))}"
        rescue Psych::Exception
          raise Invalid, "#{role} kubeconfig is not valid YAML"
        end

        private

        def entries(document, section, body_key)
          entries = document.fetch(section, [])
          raise Invalid, "kubeconfig #{section} must be a list" unless entries.is_a?(Array)

          entries.each_with_object({}) do |entry, indexed|
            raise Invalid, "kubeconfig #{section} contains an invalid entry" unless entry.is_a?(Hash)

            name = entry["name"]
            body = entry[body_key]
            unless name.is_a?(String) && !name.empty? && body.is_a?(Hash) && !indexed.key?(name)
              raise Invalid, "kubeconfig #{section} contains an invalid or duplicate entry"
            end

            indexed[name] = body
          end
        end

        def endpoint(value)
          uri = URI.parse(value.to_s)
          unless uri.is_a?(URI::HTTP) && uri.hostname && !uri.userinfo && !uri.query && !uri.fragment
            raise Invalid, "kubeconfig cluster server must be an HTTP(S) URL without credentials, query or fragment"
          end

          uri.host = uri.host.downcase.delete_suffix(".")
          uri.host = "[#{IPAddr.new(uri.hostname)}]" if uri.hostname.include?(":")
          uri.path = uri.path.sub(%r{/+\z}, "")
          uri.normalize.to_s
        rescue URI::InvalidURIError, IPAddr::InvalidAddressError
          raise Invalid, "kubeconfig cluster server is not a valid URL"
        end

        def credential_material(user)
          certificate = credential_bytes(user, "client-certificate")
          key = credential_bytes(user, "client-key")
          token_file = file_reference(user["tokenFile"], "tokenFile")
          material = [user["token"], user["password"], token_file&.strip,
                      certificate && OpenSSL::X509::Certificate.new(certificate).to_der,
                      key && OpenSSL::PKey.read(key, "").public_to_der]
          material.compact.uniq.filter_map do |value|
            raise Invalid, "kubeconfig credential must be a string" unless value.is_a?(String)

            Digest::SHA256.hexdigest(value) unless value.empty?
          end
        rescue OpenSSL::OpenSSLError, ArgumentError
          raise Invalid, "kubeconfig client certificate or key is invalid"
        end

        def credential_bytes(mapping, field)
          inline = mapping["#{field}-data"]
          return file_reference(mapping[field], field) if inline.nil?
          raise Invalid, "kubeconfig #{field}-data must be a nonempty string" unless inline.is_a?(String) && !inline.empty?

          Base64.strict_decode64(inline)
        rescue ArgumentError
          raise Invalid, "kubeconfig #{field}-data is not valid base64"
        end

        def file_reference(reference, field)
          return if reference.nil?
          raise Invalid, "kubeconfig #{field} must name a file" unless reference.is_a?(String) && !reference.empty?

          read_file(File.expand_path(reference, File.dirname(@location)), field)
        end

        def read_file(path, field)
          File.open(path, File::RDONLY | File::NONBLOCK) do |file|
            raise Invalid, "#{field} must be a readable regular file" unless file.stat.file?

            file.binmode
            file.read
          end
        rescue SystemCallError, IOError, ArgumentError
          raise Invalid, "could not read #{field}"
        end
      end

      module_function

      def verify(kubeconfig, oracle_kubeconfig)
        target = Configuration.new(kubeconfig, "target")
        oracle = Configuration.new(oracle_kubeconfig, "oracle") unless oracle_kubeconfig.nil?
        shared_servers = oracle ? target.servers.values & oracle.servers.values : []
        shared_credentials = oracle ? target.credentials & oracle.credentials : []
        unverifiable_credentials = oracle && (target.dynamic_credentials || oracle.dynamic_credentials)
        failures = []
        failures << "target kubeconfig must name exactly one cluster" unless target.clusters.size == 1
        failures << "target and oracle use the same server" unless shared_servers.empty?
        failures << "target and oracle share credentials" unless shared_credentials.empty?
        failures << "cannot verify isolation of dynamic credentials" if unverifiable_credentials
        {
          "id" => "kubeconfig_isolation", "passed" => failures.empty?,
          "clusters" => target.clusters.keys, "servers" => target.servers.values,
          "cluster_id" => target.cluster_id, "oracle_compared" => !oracle.nil?,
          "shared_server_count" => shared_servers.length, "shared_credential_count" => shared_credentials.length,
          "errors" => failures
        }
      rescue Invalid => error
        {"id" => "kubeconfig_isolation", "passed" => false, "error" => error.message}
      end
    end
  end
end
