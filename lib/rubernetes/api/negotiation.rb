# frozen_string_literal: true

require "json"
require "yaml"

require_relative "../schema/codec/kubernetes_protobuf"

module Rubernetes
  module API
    # HTTP content negotiation for the Kubernetes API surface.  The rules follow
    # k8s.io/apiserver/pkg/endpoints/handlers/negotiation: the Accept header is
    # walked in q order, each clause is matched against the endpoint's
    # serializers, and the `as`/`g`/`v` parameters select a Table or
    # PartialObjectMetadata transformation that only some encodings support.
    module Negotiation
      JSON_TYPE = "application/json"
      YAML_TYPE = "application/yaml"
      PROTOBUF_TYPE = Schema::Codec::KubernetesProtobuf::CONTENT_TYPE
      STREAM_TYPES = [JSON_TYPE, PROTOBUF_TYPE].freeze
      STANDARD_TYPES = [JSON_TYPE, YAML_TYPE, PROTOBUF_TYPE].freeze
      # Custom resources have no generated protobuf message, like upstream.
      DYNAMIC_TYPES = [JSON_TYPE, YAML_TYPE].freeze
      META_GROUP = "meta.k8s.io"
      META_VERSIONS = %w[v1 v1beta1].freeze
      TABLE_KIND = "Table"
      PARTIAL_KINDS = %w[PartialObjectMetadata PartialObjectMetadataList].freeze
      DISCOVERY_GROUP = "apidiscovery.k8s.io"
      DISCOVERY_KIND = "APIGroupDiscoveryList"
      PRETTY_USER_AGENTS = %w[curl Wget Mozilla/5.0].freeze

      # One parsed Accept clause (goautoneg.Accept).
      Clause = Struct.new(:type, :subtype, :quality, :params, keyword_init: true) do
        def wildcard_type?
          type == "*"
        end

        def wildcard_subtype?
          subtype == "*"
        end

        def matches?(media_type)
          base_type, base_subtype = media_type.split("/", 2)
          (type == base_type && subtype == base_subtype) ||
            (type == base_type && wildcard_subtype?) ||
            (wildcard_type? && wildcard_subtype?)
        end
      end

      # Result of output negotiation.
      Selection = Struct.new(:media_type, :convert, :stream, :pretty, :params, keyword_init: true) do
        def table?
          convert && convert.fetch(:kind) == TABLE_KIND
        end

        def partial_metadata?
          convert && PARTIAL_KINDS.include?(convert.fetch(:kind))
        end

        def protobuf?
          media_type == PROTOBUF_TYPE
        end

        def yaml?
          media_type == YAML_TYPE
        end

        def json?
          media_type == JSON_TYPE
        end

        def content_type
          stream ? "#{media_type};stream=#{stream}" : media_type
        end
      end

      module_function

      # goautoneg.ParseAccept: clauses ordered by q (stable) with wildcards last.
      def parse_accept(header)
        return [] if header.nil? || header.strip.empty?

        clauses = header.split(",").filter_map do |raw|
          parts = raw.strip.split(";").map(&:strip)
          media = parts.shift.to_s
          next if media.empty?

          type, subtype = media.split("/", 2)
          next if type.nil? || subtype.nil?

          params = {}
          quality = 1.0
          parts.each do |part|
            key, value = part.split("=", 2)
            next if key.nil?

            key = key.strip
            value = value.to_s.strip.delete_prefix('"').delete_suffix('"')
            if key == "q"
              parsed = Float(value, exception: false)
              quality = parsed.nil? ? 0.0 : parsed.clamp(0.0, 1.0)
            else
              params[key] = value
            end
          end
          Clause.new(type: type.strip.downcase, subtype: subtype.strip.downcase, quality: quality, params: params)
        end
        clauses.each_with_index.sort_by do |clause, index|
          [-clause.quality, clause.wildcard_type? ? 1 : 0, clause.wildcard_subtype? ? 1 : 0, index]
        end.map(&:first)
      end

      # Selects the response encoding.  +supported+ lists the endpoint's media
      # types in preference order; +stream+ requires a streaming serializer.
      def negotiate_output(accept_header, supported: STANDARD_TYPES, stream: false, table: true,
                           user_agent: nil, pretty_query: nil)
        clauses = parse_accept(accept_header)
        selection = nil
        if clauses.empty?
          candidate = stream ? supported.find { |type| STREAM_TYPES.include?(type) } : supported.first
          selection = Selection.new(media_type: candidate, convert: nil, stream: stream ? "watch" : nil,
                                    pretty: false, params: {}) if candidate
        else
          clauses.each do |clause|
            supported.each do |media_type|
              next unless clause.matches?(media_type)

              options = accept_options(clause.params, media_type, table: table)
              next if options.nil?
              next if stream && !STREAM_TYPES.include?(media_type)

              selection = Selection.new(media_type: media_type, convert: options.fetch(:convert),
                                        stream: stream ? "watch" : nil, pretty: options.fetch(:pretty),
                                        params: clause.params)
              break
            end
            break if selection
          end
        end
        if selection.nil?
          accepted = stream ? supported.select { |type| STREAM_TYPES.include?(type) }.map { |type| "#{type};stream=watch" } : supported
          raise Status::NotAcceptable.new("only the following media types are accepted: #{accepted.join(", ")}")
        end
        selection.pretty ||= pretty_print?(pretty_query, user_agent) if selection.json?
        selection
      end

      def accept_options(params, media_type, table:)
        convert = nil
        pretty = false
        params.each do |key, value|
          case key
          when "as", "g", "v"
            convert ||= {group: "", version: "", kind: ""}
            convert[{"as" => :kind, "g" => :group, "v" => :version}.fetch(key)] = value
          when "stream"
            return nil unless value.empty? || (value == "watch" && STREAM_TYPES.include?(media_type))
          when "pretty"
            pretty = value == "1" || value == "true"
          when "charset", "profile", "sv", "export"
            # Accepted but without effect on the served representation.
          end
        end
        return {convert: nil, pretty: pretty} if convert.nil?
        # apidiscovery.k8s.io/v2 APIGroupDiscoveryList is a discovery
        # representation, not an object conversion: the handler builds it and
        # the body is serialized as ordinary JSON or YAML.
        if convert[:group] == DISCOVERY_GROUP && convert[:kind] == DISCOVERY_KIND
          return nil unless [JSON_TYPE, YAML_TYPE, PROTOBUF_TYPE].include?(media_type)

          return {convert: nil, pretty: pretty}
        end
        return nil unless convert[:group] == META_GROUP && META_VERSIONS.include?(convert[:version])

        case convert[:kind]
        when TABLE_KIND
          return nil unless table && [JSON_TYPE, YAML_TYPE].include?(media_type)
        when *PARTIAL_KINDS
          # Always convertible: metadata exists for every object.
        else
          return nil
        end
        {convert: convert, pretty: pretty}
      end

      # kube-apiserver pretty-prints for browsers and command-line HTTP tools
      # unless the pretty query parameter says otherwise.
      def pretty_print?(pretty_query, user_agent)
        unless pretty_query.nil? || pretty_query.to_s.empty?
          return %w[1 t true yes y].include?(pretty_query.to_s.downcase)
        end

        agent = user_agent.to_s
        PRETTY_USER_AGENTS.any? { |prefix| agent.start_with?(prefix) }
      end

      # Selects the request decoder from Content-Type; an absent header means
      # JSON, an unknown one is 415 with the supported list.
      def negotiate_input(content_type, supported: STANDARD_TYPES)
        base = content_type.to_s.split(";", 2).first.to_s.strip.downcase
        base = supported.first if base.empty?
        return base if supported.include?(base)

        raise Status::UnsupportedMediaType.new(
          "the body of the request was in an unknown format - accepted media types include: #{supported.join(", ")}"
        )
      end

      # Sorted-key YAML matching sigs.k8s.io/yaml JSONToYAML output.
      def dump_yaml(object)
        text = ::YAML.dump(sort_keys(object), line_width: -1)
        text = text.delete_prefix("---\n").delete_prefix("--- ")
        text
      end

      def sort_keys(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, item), copy| copy[key.to_s] = item }.sort.to_h { |key, item| [key, sort_keys(item)] }
        when Array then value.map { |item| sort_keys(item) }
        else value
        end
      end

      def dump_json(object, pretty: false)
        pretty ? "#{::JSON.pretty_generate(object)}\n" : ::JSON.generate(object)
      end
    end
  end
end
