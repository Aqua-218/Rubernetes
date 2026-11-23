# frozen_string_literal: true

require "uri"

module Rubernetes
  # Kubernetes pkg/probe/http/request.go preserves repeated fields and treats
  # Host, User-Agent and Accept specially when it writes the HTTP request.
  module HTTPProbeHeaders
    USER_AGENT = "kube-probe/1.36"
    LIFECYCLE_AGENT = "kube-lifecycle/1.36"
    NAME = /\A[-a-zA-Z0-9]+\z/

    module_function

    def from_action(entries)
      grouped = {}
      Array(entries).each do |entry|
        item = entry.to_h.transform_keys(&:to_s)
        name = canonical_name(item.fetch("name"))
        value = item.fetch("value", "")
        (grouped[name] ||= []) << value
      end
      grouped.transform_values { |values| values.one? ? values.first : values }
    end

    def for_request(headers, authority)
      fields = {}
      headers.each do |name, value|
        key = canonical_name(name.to_s)
        values = Array(value)
        raise ArgumentError, "invalid HTTP probe header value" unless values.all? { |v| valid_value?(v) }

        (fields[key] ||= []).concat(values)
      end
      host = fields.fetch("Host", []).first
      fields["Host"] = [host.to_s.empty? ? authority : host]
      agent = fields.fetch("User-Agent", [USER_AGENT]).first
      fields["User-Agent"] = [agent]
      fields.delete("User-Agent") if agent.to_s.empty?
      fields["Accept"] ||= ["*/*"]
      fields.delete("Accept") if fields["Accept"].first.to_s.empty?
      fields
    end

    def canonical_name(name)
      raise ArgumentError, "invalid HTTP probe header name" unless name.is_a?(String) && NAME.match?(name)

      name.split("-", -1).map(&:capitalize).join("-")
    end

    def valid_value?(value)
      value.is_a?(String) && !value.b.match?(/[\x00-\x08\x0a-\x1f\x7f]/n)
    end

    def redirected(headers, location)
      return headers unless URI.parse(location).absolute?

      headers.reject { |name, _| name.to_s.casecmp?("Host") }
    end
  end
end
