# frozen_string_literal: true

module Rubernetes
  module Node
    class ImageCredentials
      # The kubelet's node-wide Docker config. Only the agent's configured
      # kubelet root is searched. Each process refreshes lazily every five
      # minutes, the same lifetime as the stock default Docker keyring.
      class NodeConfig
        CACHE_SECONDS = 5 * 60
        MAX_CONFIG_BYTES = 1 << 20

        def initialize(root:, monotonic: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
          @path = File.join(root, "config.json")
          @monotonic = monotonic
          @mutex = Mutex.new
          @expires_at = -Float::INFINITY
        end

        def lookup(reference)
          credentials = @mutex.synchronize do
            now = @monotonic.call
            if now >= @expires_at
              @credentials = load_credentials
              @expires_at = now + CACHE_SECONDS
            end
            @credentials
          end
          credentials.lookup(reference)
        end

        private

        def load_credentials
          keyring = ImageCredentials.new
          contents = read_config
          return keyring unless contents

          config = JSON.parse(contents)
          auths = config["auths"] if config.is_a?(Hash)
          auths.each { |registry, entry| keyring.add_auth(registry, entry) unless registry.empty? } if auths.is_a?(Hash)
          keyring
        rescue JSON::ParserError, SystemCallError
          keyring
        end

        def read_config
          File.open(@path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |file|
            stat = file.stat
            next unless stat.file? && stat.uid == Process.euid && stat.mode.nobits?(0o022) && stat.size <= MAX_CONFIG_BYTES

            contents = file.read(MAX_CONFIG_BYTES + 1)
            contents if contents && contents.bytesize <= MAX_CONFIG_BYTES
          end
        end
      end
    end
  end
end
