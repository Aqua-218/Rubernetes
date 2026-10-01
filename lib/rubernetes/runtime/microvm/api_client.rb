# frozen_string_literal: true

require "json"
require "socket"

require_relative "errors"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # Firecracker API client over its Unix domain socket
      # (spec/node/runtime.md 5.8.11).  One request per connection; the
      # HTTP/1.1 response parser is strict: header and body are each bounded
      # by 64 KiB on the request side, the whole response by 1 MiB, and a
      # duplicate Content-Length, Content-Length combined with
      # Transfer-Encoding, malformed framing, or bytes after the declared
      # body (an unrequested response) are rejected.  The configuration
      # sequence is fixed: machine config, boot source, drives, vsock,
      # network interfaces, InstanceStart.
      class APIClient
        MAX_REQUEST_HEADER_BYTES = 64 * 1024
        MAX_REQUEST_BODY_BYTES = 64 * 1024
        MAX_RESPONSE_BYTES = 1024 * 1024
        CONFIGURATION_ORDER = %i[machine_config boot_source drives vsock network_interfaces].freeze

        Response = Struct.new(:status, :headers, :body, keyword_init: true) do
          def json
            body.to_s.empty? ? nil : JSON.parse(body)
          rescue JSON::ParserError => error
            raise APIError.new("Firecracker returned invalid JSON: #{error.message}", status: status)
          end
        end

        def initialize(socket_path, timeout: 10.0)
          @socket_path = socket_path
          @timeout = timeout
          @configured = []
        end

        attr_reader :socket_path, :configured

        def describe
          request("GET", "/").json
        end

        def machine_config(vcpu_count:, mem_size_mib:, smt: false)
          step(:machine_config) { put("/machine-config", {"vcpu_count" => vcpu_count, "mem_size_mib" => mem_size_mib, "smt" => smt}) }
        end

        def boot_source(kernel_image_path:, boot_args:, initrd_path: nil)
          body = {"kernel_image_path" => kernel_image_path, "boot_args" => boot_args}
          body["initrd_path"] = initrd_path if initrd_path
          step(:boot_source) { put("/boot-source", body) }
        end

        def drive(drive_id:, path_on_host:, is_root_device:, is_read_only:, io_engine: nil)
          body = {"drive_id" => drive_id, "path_on_host" => path_on_host, "is_root_device" => is_root_device,
                  "is_read_only" => is_read_only}
          body["io_engine"] = io_engine if io_engine
          step(:drives) { put("/drives/#{drive_id}", body) }
        end

        # Hot-replaces the backing file of an existing drive (post-boot or after restore).
        def patch_drive(drive_id:, path_on_host:)
          patch("/drives/#{drive_id}", {"drive_id" => drive_id, "path_on_host" => path_on_host})
        end

        def vsock(guest_cid:, uds_path:)
          step(:vsock) { put("/vsock", {"guest_cid" => guest_cid, "uds_path" => uds_path}) }
        end

        def network_interface(iface_id:, host_dev_name:, guest_mac: nil)
          body = {"iface_id" => iface_id, "host_dev_name" => host_dev_name}
          body["guest_mac"] = guest_mac if guest_mac
          step(:network_interfaces) { put("/network-interfaces/#{iface_id}", body) }
        end

        def start!
          put("/actions", {"action_type" => "InstanceStart"})
        end

        def pause!
          patch("/vm", {"state" => "Paused"})
        end

        def resume!
          patch("/vm", {"state" => "Resumed"})
        end

        def snapshot_create!(snapshot_path:, mem_file_path:)
          put("/snapshot/create", {"snapshot_type" => "Full", "snapshot_path" => snapshot_path, "mem_file_path" => mem_file_path})
        end

        def snapshot_load!(snapshot_path:, mem_file_path:, resume_vm: false, network_overrides: [], vsock_uds_path: nil)
          body = {"snapshot_path" => snapshot_path, "mem_backend" => {"backend_type" => "File", "backend_path" => mem_file_path},
                  "resume_vm" => resume_vm, "enable_diff_snapshots" => false}
          body["network_overrides"] = network_overrides unless network_overrides.empty?
          body["vsock_override"] = {"uds_path" => vsock_uds_path} if vsock_uds_path
          put("/snapshot/load", body)
        end

        def vm_state
          request("GET", "/vm").json
        end

        # ------------------------------------------------------------------

        def put(path, body)
          request("PUT", path, body: body)
        end

        def patch(path, body)
          request("PATCH", path, body: body)
        end

        def request(method, path, body: nil)
          payload = body.nil? ? "" : JSON.generate(body)
          raise APIError.new("request body of #{payload.bytesize} bytes exceeds #{MAX_REQUEST_BODY_BYTES}") if payload.bytesize > MAX_REQUEST_BODY_BYTES

          header = "#{method} #{path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n"
          header += "Content-Type: application/json\r\nContent-Length: #{payload.bytesize}\r\n" unless body.nil?
          header += "\r\n"
          raise APIError.new("request header exceeds #{MAX_REQUEST_HEADER_BYTES} bytes") if header.bytesize > MAX_REQUEST_HEADER_BYTES

          socket = UNIXSocket.new(@socket_path)
          socket.write(header + payload)
          response = read_response(socket)
          unless response.status.between?(
            200, 299
          )
            raise APIError.new("Firecracker #{method} #{path} failed: #{fault(response)}",
                               status: response.status)
          end

          response
        rescue Errno::ENOENT, Errno::ECONNREFUSED, Errno::EPIPE, Errno::ECONNRESET, IOError => error
          raise APIError.new("Firecracker API socket #{@socket_path} is unavailable: #{error.class}: #{error.message}")
        ensure
          socket&.close
        end

        private

        def step(name)
          expected_index = CONFIGURATION_ORDER.index(name)
          done = @configured.map { |entry| CONFIGURATION_ORDER.index(entry) }
          if done.any? { |index| index > expected_index }
            raise APIError.new("configuration step #{name} must precede #{CONFIGURATION_ORDER[done.max]}")
          end

          result = yield
          @configured << name unless @configured.include?(name)
          result
        end

        def fault(response)
          document = begin
            response.json
          rescue APIError
            nil
          end
          document.is_a?(Hash) && document["fault_message"] ? document["fault_message"] : "status #{response.status}"
        end

        def read_response(socket)
          raw = String.new(encoding: Encoding::BINARY)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @timeout
          header_end = nil
          until header_end
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            raise APIError.new("Firecracker API did not answer within #{@timeout}s") if remaining <= 0 || !socket.wait_readable(remaining)

            chunk = socket.readpartial(16_384)
            raw << chunk
            raise APIError.new("Firecracker response exceeds #{MAX_RESPONSE_BYTES} bytes") if raw.bytesize > MAX_RESPONSE_BYTES

            header_end = raw.index("\r\n\r\n")
          end
          head = raw.byteslice(0, header_end)
          rest = raw.byteslice(header_end + 4, raw.bytesize)
          lines = head.split("\r\n")
          status_line = lines.shift.to_s
          match = status_line.match(%r{\AHTTP/1\.[01] (\d{3})(?: .*)?\z})
          raise APIError.new("malformed Firecracker status line #{status_line.inspect}") unless match

          headers = {}
          lines.each do |line|
            name, value = line.split(":", 2)
            raise APIError.new("malformed Firecracker header #{line.inspect}") if name.nil? || value.nil? || name.strip.empty?

            key = name.strip.downcase
            raise APIError.new("duplicate Content-Length header") if key == "content-length" && headers.key?(key)

            headers[key] = value.strip
          end
          if headers.key?("transfer-encoding")
            raise APIError.new("Content-Length combined with Transfer-Encoding") if headers.key?("content-length")

            raise APIError.new("chunked Firecracker responses are not accepted")
          end
          length = headers.key?("content-length") ? Integer(headers["content-length"], 10, exception: false) : 0
          raise APIError.new("invalid Content-Length #{headers["content-length"].inspect}") if length.nil? || length.negative?
          raise APIError.new("Firecracker response exceeds #{MAX_RESPONSE_BYTES} bytes") if length > MAX_RESPONSE_BYTES

          body = rest
          while body.bytesize < length
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            raise APIError.new("Firecracker response body timed out") if remaining <= 0 || !socket.wait_readable(remaining)

            body << socket.readpartial(length - body.bytesize)
          end
          raise APIError.new("unrequested bytes after the Firecracker response") if body.bytesize > length
          # Anything the server sends after a complete response was not requested.
          raise APIError.new("unrequested Firecracker response") if socket.wait_readable(0) && !socket.read_nonblock(1,
                                                                                                                     exception: false).nil?

          Response.new(status: Integer(match[1]), headers: headers, body: body)
        end
      end
    end
  end
end
