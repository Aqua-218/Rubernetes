# frozen_string_literal: true

module Rubernetes
  module HTTPProbeResponse
    BODY_LIMIT = 10 * 1024
    REDIRECT_CODES = [301, 302, 303, 307, 308].freeze
    REDIRECT_LIMIT = 10

    module_function

    # Both transports yield a Net::HTTPResponse while its socket is open.
    # Leave the request block at the limit so Net::HTTP cannot drain the
    # remaining body after the consumer has stopped reading.
    def capture
      body = "".b
      response = nil
      catch(:probe_body_limit) do
        yield lambda { |reply, &after_chunk|
          response = reply
          reply.read_body do |chunk|
            body << chunk.byteslice(0, BODY_LIMIT - body.bytesize)
            throw :probe_body_limit if body.bytesize == BODY_LIMIT

            after_chunk&.call
          end
        }
      end

      code = response.code.to_i
      success = code.between?(200, 399)
      text = body.force_encoding(Encoding::UTF_8).scrub
      result = {"status" => code, "success" => success, "body_bytes" => body.bytesize}
      if code.between?(300, 399)
        result.merge("location" => response["location"], "warning" => true, "message" => "Probe terminated redirects, Response body: #{text}")
      else
        result.merge("message" => success ? text : "HTTP probe failed with statuscode: #{code}")
      end
    end
  end
end
