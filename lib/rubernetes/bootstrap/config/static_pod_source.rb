# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class Config
      module StaticPodSource
        private

        HEADER_NAME = /\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\z/

        def validate_static_pod_source!(config)
          path = config["static_pod_path"]
          validate_absolute_path!(path, "rubernetes-agent.static_pod_path") unless path.nil?

          url = config["static_pod_url"]
          validate_static_pod_url!(url) unless url.nil? || url == ""
          headers = config["static_pod_url_header"]
          validate_static_pod_headers!(headers) unless headers.nil?
          %w[file_check_frequency_seconds http_check_frequency_seconds].each do |key|
            next unless config.key?(key)

            value = config[key]
            context = "rubernetes-agent.#{key}"
            validate_positive_number!(value, context)
            raise Error, "#{context} must be finite" unless value.finite?
          end
        end

        def validate_static_pod_url!(value)
          context = "rubernetes-agent.static_pod_url"
          validate_non_empty_string!(value, context)
          uri = URI.parse(value)
          raise Error, "#{context} must be an HTTP or HTTPS URL" unless uri.is_a?(URI::HTTP) && uri.hostname
        rescue URI::InvalidURIError
          raise Error, "#{context} must be an HTTP or HTTPS URL"
        end

        def validate_static_pod_headers!(headers)
          valid = headers.is_a?(Hash) && headers.all? do |name, values|
            name.is_a?(String) && HEADER_NAME.match?(name) && values.is_a?(Array) &&
              values.all? { |value| value.is_a?(String) && !value.match?(/[\r\n\x00]/) }
          end
          raise Error, "rubernetes-agent.static_pod_url_header must map header names to arrays of HTTP field values" unless valid
        end
      end
    end
  end
end
