# frozen_string_literal: true

require "json"
require "rbconfig"
require "fiddle"

module Rubernetes
  module Platform
    module Linux
      class ABIManifest
        class Error < StandardError; end
        class Mismatch < Error
          attr_reader :mismatches

          def initialize(mismatches)
            @mismatches = mismatches.freeze
            super("Linux ABI mismatch: #{mismatches.join("; ")}")
          end
        end

        ARCHITECTURES = {"x86_64" => "x86_64", "amd64" => "x86_64", "aarch64" => "aarch64", "arm64" => "aarch64"}.freeze
        MANIFEST_DIRECTORY = File.expand_path("../../../../generated/platform/linux/abi", __dir__).freeze

        attr_reader :path, :data

        def self.current_architecture
          ARCHITECTURES.fetch(RbConfig::CONFIG.fetch("host_cpu")) do
            raise Error, "unsupported Linux architecture #{RbConfig::CONFIG.fetch("host_cpu").inspect}"
          end
        end

        def self.load(architecture: current_architecture, path: nil)
          normalized = ARCHITECTURES.fetch(architecture, architecture)
          manifest_path = path || File.join(MANIFEST_DIRECTORY, "#{normalized}.json")
          new(path: manifest_path, data: JSON.parse(File.read(manifest_path)))
        rescue Errno::ENOENT, JSON::ParserError => error
          raise Error.new("cannot load ABI manifest #{manifest_path}: #{error.message}"), cause: error
        end

        def initialize(path:, data:)
          @path = File.expand_path(path).freeze
          @data = deep_freeze(data)
          validate_schema!
          freeze
        end

        def architecture
          data.fetch("architecture")
        end

        def syscall(name)
          Integer(data.fetch("syscalls").fetch(String(name)))
        end

        # Syscall numbers used by the Ruby-generated seccomp allow-list.  They
        # are kept in the architecture-specific manifest rather than inferred
        # from the host Ruby process so a cross-architecture profile cannot
        # accidentally install an x86_64 filter on arm64.
        def seccomp_syscall(name)
          Integer(data.fetch("seccomp_syscalls").fetch(String(name)))
        end

        def seccomp_syscalls
          data.fetch("seccomp_syscalls").transform_values { |value| Integer(value) }
        end

        def structure(name)
          data.fetch("structures").fetch(String(name))
        end

        def constant(group, name)
          Integer(data.fetch("constants").fetch(String(group)).fetch(String(name)))
        end

        def verify_ruby_layouts!
          mismatches = []
          expected_architecture = self.class.current_architecture
          mismatches << "architecture expected=#{expected_architecture} actual=#{architecture}" unless architecture == expected_architecture
          mismatches << "word_size expected=#{Fiddle::SIZEOF_VOIDP * 8} actual=#{data.fetch("word_size")}" unless data.fetch("word_size") == Fiddle::SIZEOF_VOIDP * 8
          expected_byte_order = [1].pack("S").getbyte(0) == 1 ? "little" : "big"
          mismatches << "byte_order expected=#{expected_byte_order} actual=#{data.fetch("byte_order")}" unless data.fetch("byte_order") == expected_byte_order
          {"clone_args" => 88, "bpf_insn" => 8, "nlmsghdr" => 16, "sockaddr_nl" => 12}.each do |name, size|
            actual = structure(name).fetch("size")
            mismatches << "#{name}.size expected=#{size} actual=#{actual}" unless actual == size
          end
          raise Mismatch, mismatches unless mismatches.empty?

          true
        end

        private

        def validate_schema!
          raise Error, "ABI schema_version must be 1" unless data["schema_version"] == 1
          raise Error, "ABI architecture is unsupported" unless ARCHITECTURES.value?(data["architecture"])
          raise Error, "ABI word_size must be 64" unless data["word_size"] == 64
          raise Error, "ABI manifest requires syscall mappings" unless data["syscalls"].is_a?(Hash)
          raise Error, "ABI manifest requires seccomp syscall mappings" unless data["seccomp_syscalls"].is_a?(Hash)
          raise Error, "ABI manifest requires structure mappings" unless data["structures"].is_a?(Hash)
          raise Error, "ABI manifest requires constant mappings" unless data["constants"].is_a?(Hash)
        end

        def deep_freeze(value)
          case value
          when Hash
            value.each { |key, child| key.freeze; deep_freeze(child) }
          when Array
            value.each { |child| deep_freeze(child) }
          end
          value.freeze
        end
      end
    end
  end
end
