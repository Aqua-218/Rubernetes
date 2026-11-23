# frozen_string_literal: true

require_relative "rubernetes/version"
require_relative "rubernetes/cleanup"
require_relative "rubernetes/schema"
require_relative "rubernetes/image"
require_relative "rubernetes/runtime"
require_relative "rubernetes/runtime/native"
require_relative "rubernetes/node"
require_relative "rubernetes/controller"
require_relative "rubernetes/watch"
require_relative "rubernetes/scheduler"
require_relative "rubernetes/network"
require_relative "rubernetes/proxy"
require_relative "rubernetes/volume"
require_relative "rubernetes/consensus"
require_relative "rubernetes/observability/history"
require_relative "rubernetes/observability/metrics"

require_relative "rubernetes/client"
require_relative "rubernetes/manifest"
require_relative "rubernetes/dra"
require_relative "rubernetes/storage/memory_store"
require_relative "rubernetes/api/status"
require_relative "rubernetes/api/patch"
require_relative "rubernetes/transport"
require_relative "rubernetes/transport/spdy"
require_relative "rubernetes/transport/websocket"
require_relative "rubernetes/runtime/cri/client"
require_relative "rubernetes/network/load_balancer_pool"

module Rubernetes
  autoload :PodAPIReferences, File.expand_path("rubernetes/pod_api_references", __dir__)
  autoload :ClaimQuotaUsage, File.expand_path("rubernetes/claim_quota_usage", __dir__)
  autoload :PodQuotaUsage, File.expand_path("rubernetes/pod_quota_usage", __dir__)
  autoload :PVCQuotaUsage, File.expand_path("rubernetes/pvc_quota_usage", __dir__)
  autoload :ServiceQuotaUsage, File.expand_path("rubernetes/service_quota_usage", __dir__)

  module Runtime
    autoload :AppArmor, File.expand_path("rubernetes/runtime/app_armor", __dir__)
  end

  module Observability
    autoload :ZPages, File.expand_path("rubernetes/observability/zpages", __dir__)
  end

  module Support
    autoload :ServiceCIDR, File.expand_path("rubernetes/support/service_cidr", __dir__)
  end

  module Schema
    autoload :GoDuration, File.expand_path("rubernetes/schema/go_duration", __dir__)
  end
end
