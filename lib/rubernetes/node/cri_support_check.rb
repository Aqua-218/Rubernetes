# frozen_string_literal: true

module Rubernetes
  module Node
    # cmd/kubelet/app/server.go getCgroupDriverFromCRI: a CRI runtime that
    # does not implement RuntimeConfig still works, but it is on its way out
    # -- kubelet_cri_losing_support{version} names the Kubernetes release
    # that will drop it.
    module CRISupportCheck
      LOSING_SUPPORT_VERSION = "1.37.0"

      module_function

      # +runtime+: the node's runtime (a Multiplexer of backends or one
      # backend); every CRI backend is asked once.  Returns the backends
      # whose runtime lacks RuntimeConfig.
      def run(runtime:, metrics: nil, logger: nil)
        backends = runtime.respond_to?(:backends) ? runtime.backends.values : [runtime]
        backends.select do |backend|
          next false unless backend.respond_to?(:client) && backend.client.respond_to?(:runtime)

          begin
            backend.client.runtime("RuntimeConfig", {}, timeout: 10)
            false
          rescue StandardError => error
            code = error.respond_to?(:code) ? error.code : nil
            unimplemented = code.to_i == Runtime::CRI::Client::UNIMPLEMENTED || error.message.to_s.match?(/unimplemented|unknown method|not implemented/i)
            if unimplemented
              metrics.cri_losing_support(LOSING_SUPPORT_VERSION) if metrics.respond_to?(:cri_losing_support)
              logger&.warn("cri.runtime_config_unimplemented", handler: backend.respond_to?(:handler) ? backend.handler : nil,
                                                              message: "CRI implementation should be updated to support RuntimeConfig") if logger.respond_to?(:warn)
            end
            unimplemented
          end
        end
      end
    end
  end
end
