# frozen_string_literal: true

require_relative "system_oom_watcher"

module Rubernetes
  module Node
    # The Linux settings verified by kubelet's setupKernelTunables.
    class KernelTunables
      EXPECTED = {
        "vm/overcommit_memory" => 1,
        "vm/panic_on_oom" => 0,
        "kernel/panic" => 10,
        "kernel/panic_on_oops" => 1,
        "kernel/keys/root_maxkeys" => 1_000_000,
        "kernel/keys/root_maxbytes" => 25_000_000
      }.freeze

      class Error < StandardError; end

      def initialize(root: "/proc/sys", user_namespace: SystemOOMWatcher.method(:user_namespace?), writer: File.method(:write))
        @root = root
        @user_namespace = user_namespace
        @writer = writer
      end

      def apply!(protect_defaults: nil, allow_user_namespace: false)
        user_namespace = @user_namespace.call
        return true if protect_defaults.nil? && !user_namespace

        ignore_write_failures = allow_user_namespace && user_namespace
        failures = EXPECTED.filter_map do |name, expected|
          path = File.join(@root, name)
          actual = Integer(File.read(path).strip, 10)
          next if actual == expected

          next "invalid kernel flag #{name.tr("/", ".")}, expected #{expected}, got #{actual}" if protect_defaults

          update(path, expected, ignore_write_failures)
        rescue SystemCallError, ArgumentError => error
          "cannot read kernel flag #{name.tr("/", ".")}: #{error.message}"
        end
        raise Error, failures.join("\n") unless failures.empty?

        true
      end

      private

      def update(path, expected, ignore_write_failures)
        @writer.call(path, expected.to_s)
        nil
      rescue SystemCallError => error
        "cannot update kernel flag #{path.delete_prefix("#{@root}/").tr("/", ".")}: #{error.message}" unless ignore_write_failures
      end
    end
  end
end
