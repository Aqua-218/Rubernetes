# frozen_string_literal: true

require "digest"
require "open3"

require_relative "errors"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # dm-verity mapping of the read-only guest rootfs.  The host kernel
      # verifies every block it serves against the pinned hash tree and root
      # hash, so a modified rootfs image fails with an I/O error instead of
      # booting; the mapped device is what the jailed VMM sees.  The
      # veritysetup tool is only invoked with the pinned inputs; the
      # decision to trust a mapping is made from the root hash recorded in
      # the artifact lock.
      class Verity
        Mapping = Struct.new(:name, :device, :root_hash, :uuid, keyword_init: true) do
          def to_h
            {"name" => name, "device" => device, "root_hash" => root_hash, "uuid" => uuid}
          end
        end

        def initialize(veritysetup: "veritysetup", mapper_root: "/dev/mapper")
          @veritysetup = veritysetup
          @mapper_root = mapper_root
        end

        # Builds a hash tree for +data_path+ into +hash_path+ and returns the root hash.
        def format(data_path, hash_path, salt: nil)
          arguments = [@veritysetup, "format", "--hash=sha256", "--data-block-size=4096", "--hash-block-size=4096"]
          arguments << "--salt=#{salt}" if salt
          arguments.push(data_path, hash_path)
          output = run!(arguments)
          root_hash = output[/Root hash:\s*([0-9a-f]{64})/, 1]
          raise VerityError, "veritysetup format did not report a root hash" if root_hash.nil?

          root_hash
        end

        # Verifies the whole tree offline; raises on mismatch.
        def verify!(data_path, hash_path, root_hash)
          run!([@veritysetup, "verify", data_path, hash_path, root_hash])
          true
        end

        def open(name, data_path, hash_path, root_hash)
          validate_name!(name)
          raise VerityError, "root hash must be 64 hex characters" unless root_hash.to_s.match?(/\A[0-9a-f]{64}\z/)

          run!([@veritysetup, "open", "--hash=sha256", data_path, name, hash_path, root_hash])
          device = File.join(@mapper_root, name)
          raise VerityError, "verity device #{device} did not appear" unless File.blockdev?(device)

          Mapping.new(name: name, device: device, root_hash: root_hash, uuid: uuid_for(name))
        end

        def close(name)
          validate_name!(name)
          return false unless active?(name)

          run!([@veritysetup, "close", name])
          true
        end

        def active?(name)
          validate_name!(name)
          _output, status = Open3.capture2e(@veritysetup, "status", name)
          status.success?
        end

        def status(name)
          output, status = Open3.capture2e(@veritysetup, "status", name)
          return nil unless status.success?

          {"name" => name, "active" => output.include?("is active"), "verified" => output.include?("status:    verified") || output.include?("status: verified"),
           "output" => output}
        end

        def uuid_for(name)
          path = "/sys/block"
          Dir.children(path).each do |device|
            dm_name = File.join(path, device, "dm", "name")
            next unless File.file?(dm_name) && File.read(dm_name).strip == name

            uuid = File.join(path, device, "dm", "uuid")
            return File.file?(uuid) ? File.read(uuid).strip : nil
          end
          nil
        rescue SystemCallError
          nil
        end

        def device_numbers(device)
          stat = File.stat(device)
          [stat.rdev_major, stat.rdev_minor]
        end

        private

        def run!(arguments)
          output, status = Open3.capture2e(*arguments)
          raise VerityError, "#{arguments.first(2).join(" ")} failed: #{output.strip}" unless status.success?

          output
        end

        def validate_name!(name)
          return if name.is_a?(String) && name.match?(/\A[a-zA-Z0-9_.-]{1,64}\z/)

          raise VerityError,
                "invalid verity mapping name #{name.inspect}"
        end
      end
    end
  end
end
