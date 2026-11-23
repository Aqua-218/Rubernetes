# frozen_string_literal: true

module Rubernetes
  module Schema
    # k8s.io/apimachinery/pkg/util/validation value formats (DNS labels and
    # subdomains, qualified names, label values, port names, path segments)
    # and metav1 LabelSelector validation, with upstream's message texts.
    module KubernetesValidator
      module_function

      # k8s.io/apimachinery/pkg/util/validation message texts.
      DNS1123_SUBDOMAIN_MSG = "a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with " \
                              "an alphanumeric character (e.g. 'example.com', regex used for validation is " \
                              "'[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')"
      DNS1123_LABEL_MSG = "a lowercase RFC 1123 label must consist of lower case alphanumeric characters or '-', and must start and end with an " \
                          "alphanumeric character (e.g. 'my-name',  or '123-abc', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?')"
      DNS1035_LABEL_MSG = "a DNS-1035 label must consist of lower case alphanumeric characters or '-', start with an alphabetic character, and end with an " \
                          "alphanumeric character (e.g. 'my-name',  or 'abc-123', regex used for validation is '[a-z]([-a-z0-9]*[a-z0-9])?')"
      QUALIFIED_NAME_FORMAT_MSG = "must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character " \
                                  "(e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')"
      QUALIFIED_NAME_PART_MSG = "name part #{QUALIFIED_NAME_FORMAT_MSG}".freeze
      LABEL_VALUE_MSG = "a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an " \
                        "alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is " \
                        "'(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')"

      def dns1123_subdomain_messages(value, byte_length: false)
        value = value.to_s
        messages = []
        length = byte_length ? value.bytesize : value.length
        messages << "must be no more than 253 #{byte_length ? "bytes" : "characters"}" if length > 253
        messages << DNS1123_SUBDOMAIN_MSG unless value.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z/)
        messages
      end

      def dns1123_label_messages(value)
        value = value.to_s
        messages = []
        messages << "must be no more than 63 characters" if value.length > 63
        messages << DNS1123_LABEL_MSG unless value.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?\z/)
        messages
      end

      def dns1035_label_messages(value)
        value = value.to_s
        messages = []
        messages << "must be no more than 63 characters" if value.length > 63
        messages << DNS1035_LABEL_MSG unless value.match?(/\A[a-z]([-a-z0-9]*[a-z0-9])?\z/)
        messages
      end

      def qualified_name_messages(value, label_key: false)
        value = value.to_s
        parts = value.empty? ? [""] : value.split("/", -1)
        messages = []
        case parts.length
        when 1
          name = parts[0]
        when 2
          prefix, name = parts
          if prefix.empty?
            messages << "prefix part must be non-empty"
          else
            messages.concat(dns1123_subdomain_messages(prefix, byte_length: label_key).map { |message| "prefix part #{message}" })
          end
        else
          format = label_key ? "a valid label key" : "a qualified name"
          return ["#{format} #{QUALIFIED_NAME_FORMAT_MSG} with an optional DNS subdomain prefix and '/' (e.g. 'example.com/MyName')"]
        end
        length = label_key ? name.bytesize : name.length
        if name.empty?
          messages << "name part must be non-empty"
        elsif length > 63
          messages << "name part must be no more than 63 #{label_key ? "bytes" : "characters"}"
        end
        messages << QUALIFIED_NAME_PART_MSG unless name.match?(/\A([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]\z/)
        messages
      end

      def label_value_messages(value, byte_length: false)
        value = value.to_s
        messages = []
        length = byte_length ? value.bytesize : value.length
        messages << "must be no more than 63 #{byte_length ? "bytes" : "characters"}" if length > 63
        messages << LABEL_VALUE_MSG unless value.match?(/\A(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?\z/)
        messages
      end

      def path_segment_name_messages(value)
        value = value.to_s
        return ["may not be '.'"] if value == "."
        return ["may not be '..'"] if value == ".."

        messages = []
        messages << "may not contain '/'" if value.include?("/")
        messages << "may not contain '%'" if value.include?("%")
        messages
      end

      # validation.IsValidPortName.
      def port_name_messages(port)
        messages = []
        messages << "must be no more than 15 characters" if port.bytesize > 15
        messages << "must contain only alpha-numeric characters (a-z, 0-9), and hyphens (-)" unless port.match?(/\A[-a-z0-9]+\z/)
        messages << "must contain at least one letter (a-z)" unless port.match?(/[a-z]/)
        messages << "must not contain consecutive hyphens" if port.include?("--")
        messages << "must not begin or end with a hyphen" if !port.empty? && (port.start_with?("-") || port.end_with?("-"))
        messages
      end

      def label_key_errors(key, path)
        if key.match?(%r{\A(?:[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]\z}) &&
           key.split("/").last.length <= 63
          return []
        end

        [issue(path, :invalid, QUALIFIED_NAME_PART_MSG)]
      end

      def label_selector_errors(selector, path, allow_invalid_expression_values: false, wire_values: false)
        return [] unless selector.is_a?(Hash)

        issues = []
        labels = fetch(selector, "matchLabels")
        if labels.is_a?(Hash)
          labels.each do |key, value|
            qualified_name_messages(key, label_key: wire_values).each do |message|
              issues << label_selector_value_issue(path + ["matchLabels"], key, message, wire_values)
            end
            label_value_messages(value, byte_length: wire_values).each do |message|
              issues << label_selector_value_issue(path + ["matchLabels"], value, message, wire_values)
            end
          end
        end
        expressions = fetch(selector, "matchExpressions")
        return issues unless expressions.is_a?(Array)

        expressions.each_with_index do |expression, index|
          next unless expression.is_a?(Hash) || (wire_values && expression.nil?)

          base = path + ["matchExpressions", index.to_s]
          values = Array(fetch(expression, "values"))
          operator = fetch(expression, "operator").to_s
          case operator
          when "In", "NotIn"
            issues << issue(base + ["values"], :required, "must be specified when `operator` is 'In' or 'NotIn'") if values.empty?
          when "Exists", "DoesNotExist"
            unless values.empty?
              issues << issue(base + ["values"], :forbidden,
                              "may not be specified when `operator` is 'Exists' or 'DoesNotExist'")
            end
          else
            value = wire_values ? go_value(InternalPodSpec.go_string(operator)) : operator
            issues << valued_issue(base + ["operator"], value, "not a valid selector operator")
          end
          key = fetch(expression, "key").to_s
          qualified_name_messages(key, label_key: wire_values).each do |message|
            issues << label_selector_value_issue(base + ["key"], key, message, wire_values)
          end
          next if allow_invalid_expression_values

          values.each_with_index do |value, value_index|
            values_path = base + ["values", value_index.to_s]
            messages = label_value_messages(value, byte_length: wire_values)
            if wire_values
              issues.concat(messages.map { |message| label_selector_value_issue(values_path, value, message, true) })
            else
              issues.concat(invalid_messages(values_path, messages))
            end
          end
        end
        issues
      end

      def label_selector_value_issue(path, value, message, wire_values)
        value = value.to_s
        value = go_value(job_status_index_quote(value)) if wire_values
        valued_issue(path, value, message)
      end
    end
  end
end
