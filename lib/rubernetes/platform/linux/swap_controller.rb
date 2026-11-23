# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module SwapController
        LIMIT = "memory.swap.max"

        module_function

        # Kubelet checks its own cgroup because the unified root has no limit.
        def available?(root: "/sys/fs/cgroup", membership: "/proc/self/cgroup")
          entry = File.foreach(membership).find { |line| line.start_with?("0::/") }
          return false unless entry

          File.file?(File.join(root, entry.delete_prefix("0::/").strip, LIMIT))
        rescue SystemCallError
          false
        end
      end
    end
  end
end
