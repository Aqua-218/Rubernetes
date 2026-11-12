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

        def validate_mapping!(value, context)
          raise Error, "#{context} must be a mapping" unless value.is_a?(Hash)
        end

        def validate_positive_number!(value, context)
          raise Error, "#{context} must be a positive number" unless value.is_a?(Numeric) && value.positive?
        end

        def validate_positive_integer!(value, context)
          raise Error, "#{context} must be a positive integer" unless value.is_a?(Integer) && value.positive?
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

        # --kube-api-qps / --kube-api-burst: the component's own limit on what
        # it sends the API server.  Unset means no client-side limit.
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
