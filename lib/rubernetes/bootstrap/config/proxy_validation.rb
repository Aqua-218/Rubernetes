# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class Config
      module ProxyValidation
        PROXY_HEALTH_SERVING_KEYS = %w[healthz_port healthz_bind_address].freeze

        private

        def validate_proxy!(process_config)
          reject_unknown_keys!(process_config, PROXY_KEYS, "rubernetes-proxy configuration")
          validate_api_rate!(process_config, "rubernetes-proxy")
          validate_proxy_addresses!(process_config["node_addresses"]) if process_config.key?("node_addresses")
          validate_proxy_serving!(process_config["serving"]) if process_config.key?("serving")
          validate_api_server!(process_config["api_server"], context: "rubernetes-proxy.api_server") if process_config.key?("api_server")
          %w[kubeconfig context node_name].each do |key|
            next unless process_config.key?(key) && !process_config[key].nil?

            validate_non_empty_string!(process_config[key], "rubernetes-proxy.#{key}")
          end
          if process_config.key?("backend") && !%w[auto ebpf bpf nftables nft iptables
                                                   memory].include?(process_config["backend"].to_s.downcase)
            raise Error, "rubernetes-proxy.backend must be one of auto, ebpf, bpf, nftables, nft, iptables, or memory"
          end
          raise Error, "rubernetes-proxy.attach must be true or false" if process_config.key?("attach") && ![true, false].include?(process_config["attach"])

          validate_sync!(process_config["sync"], "rubernetes-proxy") if process_config.key?("sync")
        end

        def validate_proxy_serving!(serving)
          context = "rubernetes-proxy.serving"
          validate_serving!(serving, "rubernetes-proxy", keys: SERVING_KEYS + PROXY_HEALTH_SERVING_KEYS)
          if serving.key?("healthz_port")
            port = serving["healthz_port"]
            raise Error, "#{context}.healthz_port must be an integer between 1 and 65535" unless port.is_a?(Integer) && port.between?(1, 65_535)
          end
          return unless serving.key?("healthz_bind_address")

          raise Error, "#{context}.healthz_port is required with healthz_bind_address" unless serving.key?("healthz_port")

          address = serving["healthz_bind_address"]
          return if address == "localhost" || (address.is_a?(String) && !address.include?("/") && IPAddr.new(address))

          raise Error, "#{context}.healthz_bind_address must be an IP address or localhost"
        rescue IPAddr::InvalidAddressError
          raise Error, "#{context}.healthz_bind_address must be an IP address or localhost"
        end

        def validate_proxy_addresses!(addresses)
          unless addresses.is_a?(Array) && addresses.all? { |address| address.is_a?(String) && !address.include?("/") && IPAddr.new(address) }
            raise Error, "rubernetes-proxy.node_addresses must be an array of IP addresses"
          end
        rescue IPAddr::InvalidAddressError
          raise Error, "rubernetes-proxy.node_addresses must be an array of IP addresses"
        end
      end
    end
  end
end
