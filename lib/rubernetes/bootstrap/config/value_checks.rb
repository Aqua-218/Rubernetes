# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class Config
      # Checks on one configuration value; each raises Config::Error naming
      # the key.
      module ValueChecks
        private

        def validate_non_empty_string!(value, context)
          raise Error, "#{context} must be a non-empty String" unless value.is_a?(String) && !value.empty?
        end

        def validate_absolute_path!(value, context)
          validate_non_empty_string!(value, context)
          raise Error, "#{context} must be an absolute path" unless value.start_with?("/")
          raise Error, "#{context} must not contain NUL" if value.include?("\0")
        end

        def validate_nat64_prefix!(prefix)
          Network::Nat64Prefix.new(prefix)
        rescue ArgumentError => error
          raise Error, "rubernetes-agent.dns.nat64_prefix: #{error.message}"
        end

        def validate_agent_resolver!(config, context)
          raise Error, "#{context}.cluster_domain must be a String" if config.key?("cluster_domain") && !config["cluster_domain"].is_a?(String)

          path = config["resolv_conf"]
          return if path == "" || !config.key?("resolv_conf") || (path.nil? && context == "rubernetes-agent")

          validate_absolute_path!(path, "#{context}.resolv_conf")
        end

        def validate_mapping!(value, context)
          raise Error, "#{context} must be a mapping" unless value.is_a?(Hash)
        end

        def validate_positive_number!(value, context)
          raise Error, "#{context} must be a positive number" unless value.is_a?(Numeric) && value.positive?
        end

        def validate_positive_integer!(value, context)
          raise Error, "#{context} must be a positive integer" unless value.is_a?(Integer) && value.positive?
        end

        def validate_agent_node_limits!(config)
          validate_positive_integer!(config["max_pods"], "rubernetes-agent.max_pods") if config.key?("max_pods")
          maximum = KubeletComponentConfig::INT32_MAX
          {"pods_per_core" => 0, "node_status_max_images" => -1}.each do |field, minimum|
            next unless config.key?(field)

            value = config.fetch(field)
            unless value.is_a?(Integer) && value.between?(minimum, maximum)
              raise Error, "rubernetes-agent.#{field} must be an integer between #{minimum} and #{maximum}"
            end
          end
        end

        def validate_linux_identity!(value, context)
          return if value.is_a?(Integer) && value.between?(0, 4_294_967_294)

          raise Error, "#{context} must be an integer between 0 and 4294967294"
        end

        def validate_file_mode!(value, context)
          valid = if value.is_a?(Integer)
                    value.between?(0, 0o7777)
                  elsif value.is_a?(String) && value.match?(/\A[0-7]{1,4}\z/)
                    Integer(value, 8).between?(0, 0o7777)
                  else
                    false
                  end
          raise Error, "#{context} must be an octal mode between 0000 and 7777" unless valid
        end

        def validate_agent_api_rate!(config)
          maximum = KubeletComponentConfig::INT32_MAX
          qps = config.fetch("kube_api_qps", 0)
          burst = config.fetch("kube_api_burst", 0)
          raise Error, "rubernetes-agent.kube_api_qps must be a non-negative number up to #{maximum}" unless qps.is_a?(Numeric) && qps.between?(0, maximum)
          raise Error, "rubernetes-agent.kube_api_burst must be a non-negative int32" unless burst.is_a?(Integer) && burst.between?(0, maximum)
        end

        # For other components, an unset rate leaves the client unlimited.
        def validate_api_rate!(process_config, process_name)
          validate_positive_number!(process_config["kube_api_qps"], "#{process_name}.kube_api_qps") if process_config.key?("kube_api_qps")
          return unless process_config.key?("kube_api_burst")

          validate_positive_integer!(process_config["kube_api_burst"], "#{process_name}.kube_api_burst")
          raise Error, "#{process_name}.kube_api_burst needs kube_api_qps" unless process_config.key?("kube_api_qps")
        end
      end
    end
  end
end
