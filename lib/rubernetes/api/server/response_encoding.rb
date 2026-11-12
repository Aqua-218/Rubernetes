# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # From a handler's decoded body to the negotiated representation: JSON, YAML
      # or protobuf, Table and PartialObjectMetadata, and watch event framing.
      module ResponseEncoding
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
        rescue Status::NotAcceptable, Status::Error => error
          error_response(error)
        end

        # A watch converts each event's object as a GET would: Table (JSON
        # only, headers on the first event alone) or PartialObjectMetadata.
        def encode_stream_response(request, response, route)
          body = response.body
          watch_convertible = route && route.resource_route? && request.method == "GET"
          selection = Negotiation.negotiate_output(request.header("accept"), supported: Negotiation::STREAM_TYPES, stream: true,
                                                                             table: watch_convertible)
          if watch_convertible && (selection.table? || selection.partial_metadata?)
            body = transform_watch_events(body, selection, request, route)
            response = Response.new(status: response.status, headers: response.headers, body: body, stream: true,
                                    unbounded: response.unbounded?)
          end
          return response unless selection.protobuf?

          codec = protobuf_codec
          framed = Enumerator.new do |yielder|
            body.each { |event| yielder << encode_watch_frame(codec, event) }
          end
          Response.new(status: response.status, headers: response.headers.merge("content-type" => selection.content_type),
                       body: framed, stream: true, unbounded: response.unbounded?)
        end

        def encode_object_response(request, response, route)
          accept = request.header("accept")
          body = response.body
          # Table/PartialObjectMetadata conversion applies to a successful read
          # of a resource; a Status or a subresource body is served as-is.
          convertible = response.status < 300 && route && route.resource_route? &&
                        %w[GET HEAD].include?(request.method) && body["kind"].to_s != "Status"
          selection = Negotiation.negotiate_output(accept, supported: Negotiation::STANDARD_TYPES, table: convertible)
          if convertible && selection.table?
            table = table_body(body, selection, request, route)
            if table
              body = table
              response = Response.new(status: response.status, headers: response.headers, body: table, stream: false)
            end
          elsif convertible && selection.partial_metadata?
            body = partial_metadata_body(body, selection)
            response = Response.new(status: response.status, headers: response.headers, body: body, stream: false)
          end
          selection = protobuf_or_next_accepted(selection, accept, convertible, body)
          if selection.protobuf?
            Response.new(status: response.status, headers: response.headers.merge("content-type" => Negotiation::PROTOBUF_TYPE),
                         body: protobuf_codec.encode(body), stream: false)
          elsif selection.yaml?
            Response.new(status: response.status, headers: response.headers.merge("content-type" => Negotiation::YAML_TYPE),
                         body: Negotiation.dump_yaml(body), stream: false)
          else
            response
          end
        end

        # An Accept header lists media types in order of preference, so a
        # body that cannot be protobuf-encoded is served as the next type
        # the client accepts -- /version and the discovery documents are
        # not protobuf-encodable, and client-go asks for
        # "application/vnd.kubernetes.protobuf, application/json" by
        # default.  406 is correct only when nothing acceptable is left.
        def protobuf_or_next_accepted(selection, accept, convertible, body)
          return selection unless selection.protobuf?

          api_version = body["apiVersion"].to_s
          kind = body["kind"].to_s
          return selection if !api_version.empty? && !kind.empty? && protobuf_codec.supports?(api_version: api_version, kind: kind)

          negotiate_without_protobuf(accept, convertible, kind)
        end

        # Re-negotiates with protobuf removed from what the server can produce.
        # Raises NotAcceptable when the client accepts nothing else.
        def negotiate_without_protobuf(accept, convertible, kind)
          supported = Negotiation::STANDARD_TYPES.reject { |type| type == Negotiation::PROTOBUF_TYPE }
          Negotiation.negotiate_output(accept, supported: supported, table: convertible)
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

        def table_body(body, selection, request, route, no_headers: false)
          TablePrinter.table_for(body, include_object: table_include_object(request), now: @clock.call.utc, no_headers: no_headers,
                                       convertor: table_convertor(route), api_version: meta_api_version(selection))
        rescue TablePrinter::PrintError => error
          raise Status::Error.new(message: error.message, code: 500, reason: "InternalError")
        end

        # asPartialObjectMetadata / asPartialObjectMetadataList: the metadata
        # alone, and a 406 when the object and the requested kind disagree.
        def partial_metadata_body(body, selection)
          api_version = meta_api_version(selection)
          wanted = selection.convert.fetch(:kind)
          list = body["kind"].to_s.end_with?("List") && body["items"].is_a?(Array)
          if wanted == "PartialObjectMetadata" && list
            raise Status::NotAcceptable.new("you requested PartialObjectMetadata, but the requested object is a list (#{body["kind"]})")
          end
          if wanted == "PartialObjectMetadataList" && !list
            raise Status::NotAcceptable.new("you requested PartialObjectMetadataList, but the requested object is not a list (#{body["kind"]})")
          end

          partial = ->(item) { {"kind" => "PartialObjectMetadata", "apiVersion" => api_version, "metadata" => item["metadata"] || {}} }
          return partial.call(body) unless list

          metadata = body["metadata"].is_a?(Hash) ? body["metadata"] : {}
          {"kind" => "PartialObjectMetadataList", "apiVersion" => api_version,
           "metadata" => metadata.slice("resourceVersion", "continue", "remainingItemCount"),
           "items" => body["items"].map { |item| partial.call(item) }}
        end

        # watchEmbeddedEncoder: every event object is transformed (a Status in
        # an ERROR event is left alone), and a Table carries its column
        # definitions on the first event only.
        def transform_watch_events(events, selection, request, route)
          table = selection.table?
          include_object = table_include_object(request) if table
          headers_sent = false
          Enumerator.new do |yielder|
            events.each do |event|
              hash = (event.is_a?(Hash) ? event : event.to_h).transform_keys(&:to_s)
              object = hash["object"]
              if object.is_a?(Hash) && object["kind"].to_s != "Status"
                hash["object"] = if table
                                   converted = TablePrinter.table_for(object, include_object: include_object, now: @clock.call.utc,
                                                                              no_headers: headers_sent, convertor: table_convertor(route),
                                                                              api_version: meta_api_version(selection))
                                   headers_sent = true
                                   converted
                                 else
                                   {"kind" => "PartialObjectMetadata", "apiVersion" => meta_api_version(selection),
                                    "metadata" => object["metadata"] || {}}
                                 end
              end
              yielder << hash
            rescue TablePrinter::PrintError
              yielder << hash
            end
          end
        end

        def encode_watch_frame(codec, event)
          hash = event.is_a?(Hash) ? event : event.to_h
          hash = hash.transform_keys(&:to_s)
          codec.encode_watch_frame(hash.fetch("type"), hash.fetch("object"))
        end
      end
    end
  end
end
