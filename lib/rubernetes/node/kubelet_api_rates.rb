# frozen_string_literal: true

require_relative "../client/rate_limiter"

module Rubernetes
  module Node
    module KubeletAPIRates
      DEFAULT_QPS = 50
      DEFAULT_BURST = 100
      REST_DEFAULT_QPS = 5

      module_function

      def configured(config)
        qps = config.fetch("kube_api_qps", DEFAULT_QPS)
        # Native YAML historically derives the burst when it sets only a positive QPS.
        burst = config["kube_api_burst"]
        burst ||= [(qps.to_f * 2).ceil, 10].max if config.key?("kube_api_qps") && qps.is_a?(Numeric) && qps.positive? && qps.to_f.finite?
        [qps, burst.nil? || burst == 0 ? DEFAULT_BURST : burst]
      end

      def client_options(config)
        qps, burst = configured(config)
        # A zero QPS reaches client-go's REST default independently in each typed API client.
        return {rate_limiter: Client::RateLimiter::ByAPIVersion.new(qps: REST_DEFAULT_QPS, burst: burst)} if qps == 0

        {qps: qps, burst: burst}
      end
    end
  end
end
