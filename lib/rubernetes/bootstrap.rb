# frozen_string_literal: true

require_relative "bootstrap/assembler"
require_relative "bootstrap/api_server_service"
require_relative "bootstrap/agent_service"
require_relative "bootstrap/control_plane_services"
require_relative "bootstrap/controller_manager_service"
require_relative "bootstrap/scheduler_service"
require_relative "bootstrap/proxy_service"
require_relative "bootstrap/cli"
require_relative "bootstrap/config"
require_relative "bootstrap/container"
require_relative "bootstrap/daemon_service"
require_relative "bootstrap/runner"
require_relative "bootstrap/shutdown"
require_relative "bootstrap/structured_logger"

module Rubernetes
  module Bootstrap
  end
end
