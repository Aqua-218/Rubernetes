# frozen_string_literal: true

require "base64"
require "delegate"
require_relative "../persistent_volume_claim_wire"

module Rubernetes
  module API
    class Server
      # From a handler's decoded body to the negotiated representation: JSON, YAML
      # protobuf or CBOR, Table and PartialObjectMetadata, and watch framing.
      module ResponseEncoding
        # A transformed watch must forward transport close to the source.
        class MappedWatch < SimpleDelegator
          include Enumerable

          def initialize(stream, &transform)
            super(stream)
            @transform = transform
          end

          def each(**)
            return enum_for(:each, **) unless block_given?

            __getobj__.each(**) do |event|
              transformed = @transform.call(event)
              if transformed.nil?
                __getobj__.close
                break
              end
              yield transformed
            end
            self
          end

          def next
            (@iterator ||= enum_for(:each)).next
          end
        end

        private

        def json_response(body, status: 200)
          Response.new(status: status, headers: {"content-type" => "application/json",
                                                 "cache-control" => "no-cache, private"}, body: body)
        end

        def error_response(error)
          status = error.to_status
          headers = {"content-type" => "application/json", "cache-control" => "no-cache, private"}
          headers["www-authenticate"] = "Bearer" if status.fetch("code") == 401
          # ErrorNegotiated: Retry-After only for a positive retryAfterSeconds.
          headers["retry-after"] = status.dig("details", "retryAfterSeconds").to_s if status.dig("details",
                                                                                                 "retryAfterSeconds").to_i.positive?
          Response.new(status: status.fetch("code"), headers: headers, body: status)
        end

        def protobuf_codec
          @protobuf_codec ||= Schema::Codec::KubernetesProtobuf.new
        end

        def response_media_types(route)
          return Negotiation::STANDARD_TYPES unless feature_gate_enabled?("CBORServingAndStorage") && cbor_response_route?(route)

          [*Negotiation::STANDARD_TYPES, Negotiation::CBOR_TYPE]
        end

        def cbor_response_route?(route)
          return false unless route
          return true if route.resource_route?
          return false unless route.kind == :resource_list

          # Built-in group-version discovery uses the group's codec. The CRD
          # discovery handlers and the root discovery endpoints have their own.
          enabled_resources.any? do |resource|
            !resource.custom? && resource.group == route.group && resource.version == route.version
          end
        end

        def watch_selection(request, route)
          supported = response_media_types(route)
          Negotiation.negotiate_output(request.header("accept"), supported: supported, stream: true,
                                                                 table: route&.resource_route? && route.watch_request?(request),
                                                                 protobuf: !route&.resource&.custom?)
        end

        # Encodes the decoded response body according to the Accept header, the
        # way k8s.io/apiserver negotiates serializers: JSON (the transport's
        # default), YAML, or Kubernetes protobuf, and for watch streams the
        # length-prefixed protobuf WatchEvent framing.  Bodies that are not
        # decoded API objects (text health endpoints, upgraded connections,
        # explicitly typed responses) pass through unchanged.
        def finalize_response(request, response, route: nil)
          return response if request.nil? || response.nil? || response.upgrade?

          response = with_warning_headers(request, response)
          return response if route && route.kind == :openapi

          content_type = response.header("content-type").to_s
          return response unless content_type.empty? || content_type.start_with?("application/json")

          if streaming_body?(response)
            encode_stream_response(request, response, route)
          elsif response.body.is_a?(Hash)
            encode_object_response(request, response, route)
          else
            response
          end
        rescue Status::NotAcceptable => error
          response.status >= 400 ? response : error_response(error)
        rescue Status::Error => error
          error_response(error)
        end

        # A watch converts each event's object as a GET would: Table (JSON
        # only, headers on the first event alone) or PartialObjectMetadata.
        def encode_stream_response(request, response, route)
          body = response.body
          watch_convertible = route&.resource_route? && route.watch_request?(request)
          selection = watch_selection(request, route)
          if watch_convertible && (selection.table? || selection.partial_metadata?)
            body = transform_watch_events(body, selection, request, route)
            response = Response.new(status: response.status, headers: response.headers, body: body, stream: true,
                                    unbounded: response.unbounded?)
          end
          return response unless selection.protobuf? || selection.cbor?

          framed = if selection.cbor?
                     MappedWatch.new(body) { |event| encode_cbor_watch_event(event) }
                   else
                     codec = protobuf_codec
                     MappedWatch.new(body) { |event| encode_watch_frame(codec, event) }
                   end
          Response.new(status: response.status, headers: response.headers.merge("content-type" => selection.content_type),
                       body: framed, stream: true, unbounded: response.unbounded?)
        end

        def websocket_watch_response(request, route, headers, stream, selection)
          stream = transform_watch_events(stream, selection, request, route) if selection.table? || selection.partial_metadata?
          events = MappedWatch.new(stream) do |event|
            if selection.cbor?
              encode_cbor_watch_event(event)
            elsif selection.protobuf?
              encode_watch_frame(protobuf_codec, event, framed: false)
            else
              JSON.generate(event.to_h) << "\n"
            end
          end
          upgrade = WatchWebSocket.new(events, binary: selection.protobuf? || selection.cbor?)
          Response.new(status: 101, headers: headers, upgrade: upgrade, unbounded: true)
        end

        def encode_object_response(request, response, route)
          accept = request.header("accept")
          body = response.body
          output_route = route
          output_route = best_effort { @router.route(request) } if output_route.nil? && accept && feature_gate_enabled?("CBORServingAndStorage")
          supported = response_media_types(output_route)
          # The route negotiates Table even when DELETE returns a Status.
          # Status itself is always returned unchanged.
          convertible = response.status < 300 && route&.resource_route? && !status_object?(body)
          # A custom GVK can resemble a built-in protobuf descriptor. The
          # request scope allows protobuf only for typed transforms and errors.
          error_status = response.status >= 400
          selection = Negotiation.negotiate_output(
            accept,
            supported: supported,
            table: table_supported?(route),
            protobuf: !route&.resource&.custom? || error_status,
            transformations: !error_status
          )
          body = PersistentVolumeClaimWire.response(body) unless selection.protobuf? || selection.partial_metadata?
          if convertible && selection.table?
            table = table_body(body, selection, request, route)
            if table
              body = table
              response = Response.new(status: response.status, headers: response.headers, body: table, stream: false)
            end
          elsif convertible && selection.partial_metadata?
            body = partial_metadata_body(body, selection, route)
            response = Response.new(status: response.status, headers: response.headers, body: body, stream: false)
          end
          selection = protobuf_or_next_accepted(selection, accept, convertible, body, supported)
          if selection.protobuf?
            Response.new(status: response.status, headers: response.headers.merge("content-type" => Negotiation::PROTOBUF_TYPE),
                         body: protobuf_codec.encode(body), stream: false)
          elsif selection.cbor?
            content_type = selection.content_type
            if convertible && selection.partial_metadata?
              content_type += ";g=#{selection.convert[:group]};v=#{selection.convert[:version]};as=#{selection.convert[:kind]}"
            end
            Response.new(status: response.status, headers: response.headers.merge("content-type" => content_type),
                         body: body, encoded_body: encode_cbor_response(body), stream: false)
          elsif selection.yaml?
            Response.new(status: response.status, headers: response.headers.merge("content-type" => Negotiation::YAML_TYPE),
                         body: Negotiation.dump_yaml(body), stream: false)
          elsif body.equal?(response.body)
            response
          else
            Response.new(status: response.status, headers: response.headers, body: body)
          end
        end

        # An Accept header lists media types in order of preference, so a
        # body that cannot be protobuf-encoded is served as the next type
        # the client accepts -- /version and the discovery documents are
        # not protobuf-encodable, and client-go asks for
        # "application/vnd.kubernetes.protobuf, application/json" by
        # default.  406 is correct only when nothing acceptable is left.
        def protobuf_or_next_accepted(selection, accept, convertible, body, supported)
          return selection unless selection.protobuf?

          api_version = body["apiVersion"].to_s
          kind = body["kind"].to_s
          return selection if !api_version.empty? && !kind.empty? && protobuf_codec.supports?(api_version: api_version, kind: kind)

          negotiate_without_protobuf(accept, convertible, kind, supported)
        end

        # Re-negotiates with protobuf removed from what the server can produce.
        # Raises NotAcceptable when the client accepts nothing else.
        def negotiate_without_protobuf(accept, convertible, kind, supported)
          Negotiation.negotiate_output(accept, supported: supported - [Negotiation::PROTOBUF_TYPE], table: convertible)
        rescue Status::NotAcceptable
          raise Status::NotAcceptable.new("#{kind.to_s.empty? ? "the response" : kind} cannot be encoded as #{Negotiation::PROTOBUF_TYPE}")
        end

        # TableOptions.includeObject (ValidateTableOptions): Metadata when
        # empty, and anything but Metadata, Object or None is a bad request.
        def table_include_object(request)
          value = query(request, "includeObject").to_s
          return "Metadata" if value.empty?
          return value if %w[Object Metadata None].include?(value)

          raise Status::BadRequest.new("Unable to convert to Table as requested: includeObject: Invalid value: #{value.inspect}: " \
                                       "must be 'Metadata', 'Object', 'None', or empty")
        end

        def meta_api_version(selection)
          "#{Negotiation::META_GROUP}/#{selection.convert.fetch(:version)}"
        end

        # The TableConvertor registered for the route's resource: a custom
        # resource's served-version printer columns, otherwise chosen by kind.
        def table_convertor(route)
          resource = route&.resource
          if resource && !resource.is_a?(Resource)
            resource = @registry.find_gvr(group: route.group.to_s, version: route.version.to_s,
                                          resource: resource.to_s)
          end
          return nil unless resource&.custom?
          return nil if route.subresource && !route.subresource.to_s.empty? && route.subresource.to_s != "status"

          [:crd, TablePrinter.crd_columns(resource.printer_columns)]
        end

        def table_supported?(route)
          return false unless route&.resource_route?
          return route.resource.verbs.include?("list") if route.subresource.nil?

          %w[status scale].include?(route.subresource)
        end

        def table_body(body, selection, request, route, no_headers: false)
          TablePrinter.table_for(body, include_object: table_include_object(request), now: @clock.call.utc, no_headers: no_headers,
                                       convertor: table_convertor(route), api_version: meta_api_version(selection))
        rescue TablePrinter::PrintError => error
          raise Status::Error.new(message: error.message, code: 500, reason: "InternalError")
        end

        # asPartialObjectMetadata / asPartialObjectMetadataList: the metadata
        # alone, and a 406 when the object and the requested kind disagree.
        def partial_metadata_body(body, selection, route)
          api_version = meta_api_version(selection)
          wanted = selection.convert.fetch(:kind)
          list = body["kind"].to_s.end_with?("List") && body["items"].is_a?(Array)
          if wanted == "PartialObjectMetadata" && list
            raise Status::NotAcceptable.new("you requested PartialObjectMetadata, but the requested object is a list (#{metadata_object_type(body, route)})")
          end

          if wanted == "PartialObjectMetadataList" && !list
            object_type = metadata_object_type(body, route)
            raise Status::NotAcceptable.new("you requested PartialObjectMetadataList, but the requested object is not a list (#{object_type})")
          end

          partial = ->(item) { {"kind" => "PartialObjectMetadata", "apiVersion" => api_version, "metadata" => item["metadata"] || {}} }
          return partial.call(body) unless list

          metadata = body["metadata"].is_a?(Hash) ? body["metadata"] : {}
          {"kind" => "PartialObjectMetadataList", "apiVersion" => api_version,
           "metadata" => metadata.slice("resourceVersion", "continue", "remainingItemCount"),
           "items" => body["items"].map { |item| partial.call(item) }}
        end

        def metadata_object_type(body, route)
          if route&.resource&.custom? && route.subresource != "scale"
            return body["items"].is_a?(Array) && body["kind"] == route.resource.list_kind ? "*unstructured.UnstructuredList" : "*unstructured.Unstructured"
          end

          version = body["apiVersion"].to_s
          package = version.include?("/") ? version.split(%r{[./]}, 2).first : "core"
          "*#{package}.#{body["kind"]}"
        end

        # watchEmbeddedEncoder: every event object is transformed (a Status in
        # an ERROR event is left alone), and a Table carries its column
        # definitions on the first event only.
        def transform_watch_events(events, selection, request, route)
          table = selection.table?
          include_object = table_include_object(request) if table
          headers_sent = false
          MappedWatch.new(events) do |event|
            hash = (event.is_a?(Hash) ? event : event.to_h).transform_keys(&:to_s)
            object = hash["object"]
            if object.is_a?(Hash) && !status_object?(object)
              hash["object"] = if table
                                 converted = TablePrinter.table_for(object, include_object: include_object, now: @clock.call.utc,
                                                                            no_headers: headers_sent, convertor: table_convertor(route),
                                                                            api_version: meta_api_version(selection))
                                 headers_sent = true
                                 converted
                               else
                                 partial_metadata_body(object, selection, route)
                               end
            end
            hash
          rescue TablePrinter::PrintError
            hash
          rescue Status::NotAcceptable
            # Headers have already been sent. Like the upstream watch encoder,
            # end the stream at the first object the selected codec cannot emit.
            nil
          end
        end

        def encode_cbor_watch_event(event)
          hash = event.is_a?(Hash) ? event : event.to_h
          object = hash["object"] || hash[:object]
          # The watch serializer embeds the independently tagged object as a
          # RawExtension (a CBOR data item) within the outer WatchEvent map.
          tagged = Schema::Codec::CBOR::TaggedValue.new(55_799, cbor_typed_value(object))
          encode_cbor_response({"type" => hash["type"] || hash[:type], "object" => tagged})
        end

        def status_object?(object)
          object["apiVersion"] == "v1" && object["kind"] == "Status"
        end

        def encode_cbor_response(body)
          Schema::Codec::KubernetesCBOR.encode(cbor_typed_value(body), deterministic: false)
        end

        # The public object model represents Go []byte fields as base64 strings.
        # The CBOR serializer emits those as tag 22 enclosing the original bytes.
        def cbor_typed_value(object)
          return object unless object.is_a?(Hash) && object["apiVersion"].is_a?(String) && object["kind"].is_a?(String)

          group_version = object["apiVersion"]
          path = group_version.include?("/") ? "v3/apis/#{group_version}.json" : "v3/api/#{group_version}.json"
          components = @openapi.static_document(path)&.dig("components", "schemas")
          return object unless components

          schema = components.each_value.find do |candidate|
            Array(candidate["x-kubernetes-group-version-kind"]).any? do |gvk|
              [gvk["group"], gvk["version"]].reject(&:empty?).join("/") == group_version && gvk["kind"] == object["kind"]
            end
          end
          schema ? cbor_typed_field(object, schema, components) : object
        end

        def cbor_typed_field(value, schema, components)
          return value unless schema.is_a?(Hash)

          reference = schema["$ref"]
          return cbor_typed_field(value, components[reference.split("/").last], components) if reference

          case value
          when String
            return value unless schema["format"] == "byte"

            Schema::Codec::CBOR::Base64Bytes.new(Base64.strict_decode64(value))
          when Array
            value.map { |entry| cbor_typed_field(entry, schema["items"], components) }
          when Hash
            properties = schema["properties"] || {}
            value.to_h do |name, entry|
              [name, cbor_typed_field(entry, properties[name] || schema["additionalProperties"], components)]
            end
          else
            value
          end
        rescue ArgumentError
          value
        end

        def encode_watch_frame(codec, event, framed: true)
          hash = event.is_a?(Hash) ? event : event.to_h
          hash = hash.transform_keys(&:to_s)
          payload = codec.encode_watch_event(hash.fetch("type"), hash.fetch("object"))
          framed ? codec.frame(payload) : payload
        end
      end
    end
  end
end
