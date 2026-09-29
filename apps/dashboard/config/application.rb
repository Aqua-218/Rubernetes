require_relative "boot"

require "rails"
# Pick the frameworks you want:
require "active_model/railtie"
require "active_job/railtie"
require "action_controller/railtie"
# require "action_mailer/railtie"
# require "action_mailbox/engine"
# require "action_text/engine"
require "action_view/railtie"
require "rails/test_unit/railtie"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

# The dashboard talks to the cluster through the Rubernetes client library
# that lives two directories up; no gem build is involved.
RUBERNETES_LIB = File.expand_path("../../../lib", __dir__)
$LOAD_PATH.unshift(RUBERNETES_LIB) unless $LOAD_PATH.include?(RUBERNETES_LIB)
require_relative "../lib/dashboard/config"

module Dashboard
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 8.1

    # Please, add to the `ignore` list any other `lib` subdirectories that do
    # not contain `.rb` files, or that should not be reloaded or eager loaded.
    # Common ones are `templates`, `generators`, or `middleware`, for example.
    config.autoload_lib(ignore: %w[assets tasks])

    # Configuration for the application, engines, and railties goes here.
    #
    # These settings can be overridden in specific environments using the files
    # in config/environments, which are processed later.
    #
    # config.time_zone = "Central Time (US & Canada)"
    # config.eager_load_paths << Rails.root.join("extras")

    # Don't generate system test files.
    config.generators.system_tests = nil

    # Host authorization: the Ingress forwards the public name
    # (dashboard.<domain>) as the Host header, which the development default
    # (localhost and IP literals) would reject.  DASHBOARD_HOSTS lists the
    # names, empty disables the check (see Dashboard::Config.allowed_hosts).
    hosts = Dashboard::Config.allowed_hosts
    if hosts.empty?
      config.hosts.clear
    else
      config.hosts.concat(hosts)
    end
    config.host_authorization = {exclude: ->(request) { request.path == "/up" }}
  end
end
