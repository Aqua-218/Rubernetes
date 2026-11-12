# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # The pods/services/nodes `proxy` subresource: target resolution, the raw
      # HTTP exchange with the backend, and link rewriting in what comes back.
      module ProxySubresource
        private

        # pkg/registry/core/{pod,service,node}/rest: the `proxy` subresource
        # relays a request to a Pod, a Service endpoint or a node's kubelet.
        # The name may carry a scheme and a port ("https:name:8443"), and every
        # path segment after `proxy` belongs to the proxied request.
        PROXY_HOP_HEADERS = %w[connection keep-alive proxy-authenticate proxy-authorization te trailer
                               transfer-encoding upgrade host content-length authorization].freeze

        PROXY_TIMEOUT_SECONDS = Float(ENV.fetch("RUBERNETES_PROXY_TIMEOUT", "30"))

        PROXY_MAX_BODY_BYTES = 32 * 1024 * 1024

        def proxy_response(request, route)
          redirect = proxy_root_redirect(request)
          return redirect if redirect

          scheme, name, port = split_scheme_name_port(route.name)
          target = case route.resource.resource
                   when "pods" then pod_proxy_target(route, name, port)
                   when "services" then service_proxy_target(route, name, port)
                   else node_proxy_target(route, name, port)
                   end
          scheme ||= target[:scheme]
          uri = URI("#{scheme}://#{format_proxy_host(target.fetch(:host))}:#{target.fetch(:port)}")
          uri.path = "/#{route.subresource_path.to_s.delete_prefix("/")}"
          uri.path = "/" if uri.path == "/"
          query = request.query.reject { |key, _| key == "path" }
          uri.query = encode_proxy_query(query) unless query.empty?
          perform_proxy(request, uri, prefix: proxy_path_prefix(request, route), tls: target[:tls])
        end

        # apimachinery's proxy handler answers GET/HEAD on the bare proxy root
        # (".../proxy", no trailing slash) with 301 to ".../proxy/" so the
        # backend's relative links resolve; "[sig-network] Proxy version v1 A
        # set of valid responses" checks that 301 for pods and services.
        # request.path has had its trailing slash stripped, so it says "/proxy"
        # for both ".../proxy" and ".../proxy/" and redirecting on it sent
        # ".../proxy/" to itself for ever.  The client's own spelling decides.
        def proxy_root_redirect(request)
          raw_path = request.raw_path.to_s.split("?", 2).first.to_s
          return nil unless %w[GET HEAD].include?(request.method.to_s) && raw_path.end_with?("/proxy")

          location = "#{raw_path}/"
          location = "#{location}?#{encode_proxy_query(request.query)}" unless request.query.empty?
          Response.new(status: 301, headers: {"location" => location, "content-type" => "text/html; charset=utf-8"},
                       body: "<a href=\"#{location}\">Moved Permanently</a>.\n\n")
        end

        def encode_proxy_query(query)
          URI.encode_www_form(query.flat_map { |key, value| Array(value).map { |item| [key.to_s, item.to_s] } })
        end

        # Everything in the request path up to and including "/proxy": the prefix
        # the proxied server's own absolute links have to be rewritten with.  It
        # is the request path minus the part that was forwarded, because a
        # namespace may itself be called "proxy" and searching the path for the
        # word would find that one.
        def proxy_path_prefix(request, route)
          path = request.path.to_s.split("?", 2).first.to_s
          remainder = route.subresource_path.to_s.delete_prefix("/")
          unless remainder.empty?
            suffix = "/#{remainder}"
            path = path[0, path.length - suffix.length] if path.end_with?(suffix)
          end
          path = path.chomp("/") if path.length > 1
          path
        end

        def split_scheme_name_port(value)
          parts = value.to_s.split(":")
          case parts.length
          when 1 then [nil, parts[0], nil]
          when 2
            # "name:port" or "scheme:name"; a numeric or named port is the
            # second form only when it is not a known scheme.
            %w[http https].include?(parts[0]) ? [parts[0], parts[1], nil] : [nil, parts[0], parts[1]]
          else [parts[0], parts[1], parts[2]]
          end
        end

        def format_proxy_host(host)
          host.to_s.include?(":") ? "[#{host}]" : host.to_s
        end

        def pod_proxy_target(route, name, port)
          pod = begin
            @store.get(resource: route.resource, namespace: storage_namespace(route, operation: :get), name: name)
          rescue MemoryStore::NotFound
            raise Status::NotFound.new("pods #{name.inspect} not found", details: resource_details(route))
          end
          address = pod.dig("status", "podIP").to_s
          raise Status::ServiceUnavailable.new("pod #{name.inspect} has no IP address") if address.empty?

          {host: address, port: resolve_pod_port(pod, port), scheme: "http"}
        end

        def resolve_pod_port(pod, port)
          if port.nil? || port.to_s.empty?
            # pod.ResourceLocation: no port means the first port the first
            # container that declares one exposes, and only then plain :80.
            first = Array(pod.dig("spec", "containers")).lazy.flat_map { |container| Array(container["ports"]) }.first
            return first && first["containerPort"] ? Integer(first["containerPort"]) : 80
          end
          return Integer(port) if port.to_s.match?(/\A\d+\z/)

          containers = Array(pod.dig("spec", "containers")) + Array(pod.dig("spec", "initContainers"))
          entry = containers.flat_map { |container| Array(container["ports"]) }.find { |value| value["name"].to_s == port.to_s }
          raise Status::BadRequest.new("pod port #{port.inspect} was not found") if entry.nil?

          Integer(entry["containerPort"])
        end

        # A Service proxies to one of its ready endpoints, not to the ClusterIP:
        # the API server has no kube-proxy datapath of its own.
        def service_proxy_target(route, name, port)
          namespace = storage_namespace(route, operation: :get)
          service = begin
            @store.get(resource: route.resource, namespace: namespace, name: name)
          rescue MemoryStore::NotFound
            raise Status::NotFound.new("services #{name.inspect} not found", details: resource_details(route))
          end
          service_port = select_service_port(service, port)
          endpoint = ready_endpoint_for(namespace, name, service_port)
          raise Status::ServiceUnavailable.new("no endpoints available for service #{name.inspect}") if endpoint.nil?

          {host: endpoint.fetch(:address), port: endpoint.fetch(:port), scheme: endpoint.fetch(:scheme)}
        end

        def select_service_port(service, port)
          ports = Array(service.dig("spec", "ports"))
          return ports.first || {} if port.nil? || port.to_s.empty?

          match = if port.to_s.match?(/\A\d+\z/)
                    ports.find { |entry| entry["port"].to_i == port.to_i }
                  else
                    ports.find { |entry| entry["name"].to_s == port.to_s }
                  end
          raise Status::BadRequest.new("service port #{port.inspect} was not found") if match.nil?

          match
        end

        def ready_endpoint_for(namespace, service_name, service_port)
          descriptor = @registry.find_gvr(group: "discovery.k8s.io", version: "v1", resource: "endpointslices")
          return nil if descriptor.nil?

          # StoreAdapter#list requires `selectors:`; without it the call raised
          # ArgumentError, every Service resolved to "no endpoints", and every
          # webhook fell back to a *.svc name the host cannot resolve.
          slices = @store.list(resource: descriptor, namespace: namespace, selectors: nil)
          items = slices.items.select { |slice| slice.dig("metadata", "labels", "kubernetes.io/service-name").to_s == service_name.to_s }
          port_name = service_port["name"].to_s
          items.each do |slice|
            numbers = Array(slice["ports"]).select { |entry| port_name.empty? || entry["name"].to_s == port_name }
              .filter_map { |entry| entry["port"] }
            next if numbers.empty?

            address = Array(slice["endpoints"]).find { |endpoint| endpoint.dig("conditions", "ready") != false }
            next if address.nil?

            value = Array(address["addresses"]).first
            next if value.to_s.empty?

            return {address: value, port: Integer(numbers.first), scheme: "http"}
          end
          nil
        end

        def node_proxy_target(route, name, port)
          node = begin
            @store.get(resource: route.resource, namespace: :cluster, name: name)
          rescue MemoryStore::NotFound
            raise Status::NotFound.new("nodes #{name.inspect} not found", details: resource_details(route))
          end
          # The node proxy dials the kubelet where exec and logs do: the
          # agent-published streaming address wins over status.addresses, which
          # may name an interface the kubelet does not listen on.
          announced = node.dig("metadata", "annotations", NodeEndpointResolver::STREAMING_ADDRESS_ANNOTATION).to_s
          addresses = Array(node.dig("status", "addresses"))
          entry = %w[InternalIP ExternalIP Hostname].filter_map do |type|
            addresses.find { |address| address["type"] == type && !address["address"].to_s.empty? }
          end.first
          entry = {"address" => announced} unless announced.empty?
          raise Status::ServiceUnavailable.new("node #{name.inspect} has no address") if entry.nil?

          # "Port" is v1.DaemonEndpoint's actual JSON field name; the lowercase
          # spelling is accepted for a Node written by an older agent.
          endpoint = node.dig("status", "daemonEndpoints", "kubeletEndpoint")
          endpoint = {} unless endpoint.is_a?(Hash)
          advertised = (endpoint["Port"] || endpoint["port"]).to_i
          default_port = advertised.positive? ? advertised : 10_250
          # A request for the well-known kubelet port reaches the port this
          # kubelet advertises: several agents share one host here, so none of
          # them can own 10250, and clients (the e2e framework's node dumps)
          # hardcode it.
          requested = port.to_s.empty? || port.to_s == "10250" ? default_port : port
          {host: entry["address"], port: Integer(requested), scheme: kubelet_scheme, tls: kubelet_client_tls}.compact
        end

        # The exchange is written directly on a socket rather than through
        # Net::HTTP: the proxy must forward one request verbatim, including
        # methods and headers a higher-level client would rewrite, and the
        # upgrade path already speaks to node endpoints this way.
        def perform_proxy(request, uri, prefix: "", tls: nil)
          socket = open_proxy_socket(uri, tls: tls)
          begin
            socket.write(proxy_request_bytes(request, uri))
            socket.flush
            status, headers, leftover = read_proxy_head(socket)
            body = read_proxy_body(socket, headers, leftover)
            forwarded = {}
            headers.each do |name, values|
              next if PROXY_HOP_HEADERS.include?(name)

              forwarded[name] = values.length == 1 ? values.first : values
            end
            forwarded["content-type"] ||= "application/octet-stream"
            forwarded["location"] = rewrite_proxy_url(forwarded["location"], prefix) if forwarded["location"]
            body = rewrite_proxy_html(body, forwarded["content-type"], prefix)
            forwarded["content-length"] = body.bytesize.to_s if forwarded.key?("content-length")
            Response.new(status: status, headers: forwarded, body: body, stream: false)
          ensure
            begin
              socket.close unless socket.closed?
            rescue IOError, SystemCallError
              nil
            end
          end
        rescue Status::Error
          raise
        rescue Errno::ETIMEDOUT, Timeout::Error
          raise Status::ServiceUnavailable.new("proxy request to #{uri} timed out")
        rescue SystemCallError, IOError, OpenSSL::SSL::SSLError => error
          raise Status::ServiceUnavailable.new("proxy request to #{uri} failed: #{error.message}")
        end

        # The API server rewrites the absolute links a proxied server returns so
        # that a client following them stays inside the proxy
        # (apimachinery util/proxy/transport.go Transport.RoundTrip: "rewrite
        # URLs in the body of the response").  A server behind
        # /api/v1/namespaces/ns/pods/name/proxy has no idea it is being proxied
        # and answers with href="/rewriteme"; without the rewrite that link
        # points at the API server's own root, which is what "[sig-network] Proxy
        # version v1 should proxy through a service and a pod" checks.
        #
        # Only the attributes that carry a URL are touched, and only in a
        # text/html response, exactly as upstream's atomsToAttrs table does.
        PROXY_REWRITE_ATTRIBUTES = {
          "a" => %w[href], "applet" => %w[codebase], "area" => %w[href], "audio" => %w[src],
          "base" => %w[href], "blockquote" => %w[cite], "body" => %w[background],
          "button" => %w[formaction], "command" => %w[icon], "del" => %w[cite], "embed" => %w[src],
          "form" => %w[action], "frame" => %w[longdesc src], "head" => %w[profile],
          "html" => %w[manifest], "iframe" => %w[longdesc src], "img" => %w[longdesc src usemap],
          "input" => %w[src usemap formaction], "ins" => %w[cite], "link" => %w[href],
          "object" => %w[classid codebase data usemap], "q" => %w[cite], "script" => %w[src],
          "source" => %w[src], "video" => %w[poster src]
        }.freeze

        def rewrite_proxy_html(body, content_type, prefix)
          return body if prefix.to_s.empty? || body.nil? || body.empty?
          return body unless content_type.to_s.split(";", 2).first.to_s.strip.downcase == "text/html"

          text = body.dup.force_encoding(Encoding::UTF_8)
          return body unless text.valid_encoding?

          text.gsub(%r{<\s*([A-Za-z][A-Za-z0-9]*)((?:\s+[^<>]*?)?)(/?)>}m) do
            tag = Regexp.last_match(1)
            attributes = Regexp.last_match(2)
            closing = Regexp.last_match(3)
            names = PROXY_REWRITE_ATTRIBUTES[tag.downcase]
            next Regexp.last_match(0) if names.nil? || attributes.empty?

            rewritten = attributes.gsub(/(\s)([A-Za-z-]+)(\s*=\s*)(["'])(.*?)\4/m) do
              space = Regexp.last_match(1)
              attribute = Regexp.last_match(2)
              equals = Regexp.last_match(3)
              quote = Regexp.last_match(4)
              value = Regexp.last_match(5)
              next Regexp.last_match(0) unless names.include?(attribute.downcase)

              "#{space}#{attribute}#{equals}#{quote}#{rewrite_proxy_url(value, prefix)}#{quote}"
            end
            "<#{tag}#{rewritten}#{closing}>"
          end.b
        end

        # transport.go rewriteURL: only a same-host, absolute path is rewritten.
        # A relative link already resolves against the proxied path, and a link
        # to another host is not ours to redirect.
        def rewrite_proxy_url(value, prefix)
          target = value.to_s
          return target if target.empty? || prefix.to_s.empty?

          parsed = begin
            URI.parse(target)
          rescue URI::InvalidURIError
            return target
          end
          return target unless parsed.host.nil? || parsed.host.empty?
          return target unless parsed.path.to_s.start_with?("/")
          return target if parsed.path.to_s == prefix || parsed.path.to_s.start_with?("#{prefix}/")

          trailing = parsed.path.end_with?("/") && parsed.path != "/"
          joined = File.join(prefix, parsed.path)
          joined = "#{joined}/" if trailing && !joined.end_with?("/")
          parsed.path = joined
          parsed.to_s
        end

        # +tls+: the kubelet client credentials for a node proxy.
        def open_proxy_socket(uri, tls: nil)
          # URI#host keeps the brackets of an IPv6 literal ("[fd00::2]"), which
          # getaddrinfo does not resolve; URI#hostname is the bare address.
          # Every pods/services/nodes proxy to an IPv6 target answered 500
          # ("[sig-network] Proxy version v1 A set of valid responses ...").
          tcp = Security::Egress.tcp_socket(uri.hostname, uri.port, "cluster", connect_timeout: PROXY_TIMEOUT_SECONDS)
          begin
            tcp.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
          rescue SystemCallError
            nil # an egress tunnel over a Unix socket
          end
          return tcp unless uri.scheme == "https"

          ssl = OpenSSL::SSL::SSLSocket.new(tcp, NodeEndpointResolver::KubeletClientTLS.context(tls))
          ssl.hostname = uri.hostname unless uri.hostname.to_s.match?(/\A[\d.:]+\z/)
          ssl.sync_close = true
          ssl.connect
          ssl
        end

        def proxy_request_bytes(request, uri)
          lines = ["#{request.method} #{uri.request_uri} HTTP/1.1", "Host: #{uri.host}:#{uri.port}"]
          request.headers.each do |name, value|
            next if PROXY_HOP_HEADERS.include?(name.to_s.downcase)

            lines << "#{name}: #{value}"
          end
          body = request_raw_body(request).to_s
          lines << "Content-Length: #{body.bytesize}"
          lines << "Connection: close"
          "#{lines.join("\r\n")}\r\n\r\n#{body}".b
        end

        PROXY_MAX_HEAD_BYTES = 64 * 1024

        def read_proxy_head(socket)
          buffer = "".b
          until (index = buffer.index("\r\n\r\n"))
            chunk = socket.readpartial(4096)
            buffer << chunk
            raise Status::ServiceUnavailable.new("proxied response head is too large") if buffer.bytesize > PROXY_MAX_HEAD_BYTES
          end
          head = buffer.byteslice(0, index)
          leftover = buffer.byteslice((index + 4)..) || "".b
          lines = head.split("\r\n")
          status = lines.shift.to_s.split(" ", 3)[1].to_i
          headers = Hash.new { |hash, key| hash[key] = [] }
          lines.each do |line|
            name, _, value = line.partition(":")
            next if value.empty? && !line.include?(":")

            headers[name.strip.downcase] << value.strip
          end
          [status, headers, leftover]
        end

        def read_proxy_body(socket, headers, leftover)
          length = headers["content-length"].first
          body = leftover.dup
          if length
            limit = Integer(length)
            raise Status::ServiceUnavailable.new("proxied response exceeds #{PROXY_MAX_BODY_BYTES} bytes") if limit > PROXY_MAX_BODY_BYTES

            while body.bytesize < limit
              chunk = socket.read(limit - body.bytesize)
              break if chunk.nil? || chunk.empty?

              body << chunk
            end
          else
            while (chunk = socket.read(65_536))
              body << chunk
              raise Status::ServiceUnavailable.new("proxied response exceeds #{PROXY_MAX_BODY_BYTES} bytes") if body.bytesize > PROXY_MAX_BODY_BYTES
            end
            body = decode_chunked_body(body) if headers["transfer-encoding"].any? { |value| value.downcase.include?("chunked") }
          end
          body
        rescue EOFError
          body || "".b
        end

        def decode_chunked_body(raw)
          result = "".b
          offset = 0
          loop do
            line_end = raw.index("\r\n", offset)
            break if line_end.nil?

            size = raw.byteslice(offset, line_end - offset).split(";").first.to_s.strip.to_i(16)
            break if size.zero?

            result << raw.byteslice(line_end + 2, size).to_s
            offset = line_end + 2 + size + 2
          end
          result
        end

        def request_raw_body(request)
          value = request.body
          return nil if value.nil?

          value.is_a?(String) ? value : value.to_s
        end
      end
    end
  end
end
