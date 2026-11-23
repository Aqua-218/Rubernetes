# frozen_string_literal: true

require "digest"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # Kubelet-generated files have guest-local inodes and no shared host mount.
      module ContainerFiles
        POD_PATHS = %w[/etc/hosts /etc/hostname /etc/resolv.conf].freeze
        TERMINATION = "termination-message"
        NAMES = (POD_PATHS.map { |path| File.basename(path) } + [TERMINATION]).freeze
        ROOT = "/run/rubernetes/files/containers"

        def self.directory(id)
          File.join(ROOT, Digest::SHA256.hexdigest(id))
        end
      end
    end
  end
end
