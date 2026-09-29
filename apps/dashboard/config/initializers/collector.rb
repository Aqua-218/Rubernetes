# frozen_string_literal: true

# Start the scrape/evaluation loop inside the web process (the head of the
# time-series store lives here, as in a Prometheus server).  Disabled in the
# test environment and with DASHBOARD_COLLECTOR=0; `bin/rails runner
# "Dashboard::Runtime.current.collector.round"` runs one round by hand.
Rails.application.config.after_initialize do
  next if Rails.env.test?
  next unless Dashboard::Config.collector_enabled?
  next if defined?(Rails::Console) || File.basename($PROGRAM_NAME) == "rake"

  runtime = Dashboard::Runtime.current
  runtime.start
  at_exit { runtime.stop }
end
