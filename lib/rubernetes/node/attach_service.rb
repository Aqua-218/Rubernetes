# frozen_string_literal: true

require_relative "container_stream_service"

module Rubernetes
  module Node
    # Attaches to an existing container process.  Attach intentionally shares
    # the exec stream contract but never accepts a command, because the
    # runtime must preserve the process selected by the container lifecycle.
    class AttachService < ContainerStreamService
      def attach(container_id = nil, tty: false, stdin: false, stdout: true, stderr: false,
                 request_id: nil, identity: nil, **options)
        open_container_stream(
          :attach, container_id,
          request_id: request_id, identity: identity, options: options,
          tty: tty, stdin: stdin, stdout: stdout, stderr: stderr
        )
      end

      alias call attach
      alias open attach
    end

    Attach = AttachService
  end
end
