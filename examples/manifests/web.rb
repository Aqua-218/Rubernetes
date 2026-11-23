# frozen_string_literal: true

# A web application with shared configuration and CPU-based scaling in production.
#
#   rubectl render -f examples/manifests/web.rb --allow-code -o yaml
#   rubectl render -f examples/manifests/web.rb --allow-code --env APP_ENV | kubectl apply -f -

def production? = ENV["APP_ENV"] == "production"

settings = config_map "web-config" do
  data LOG_LEVEL: production? ? "info" : "debug", GREETING: "hello"
end

web = deployment "web" do
  rollout_on settings

  container "nginx", image: "nginx:1.27" do
    port 80, name: "http"
    cpu request: "100m", limit: "500m"
    memory request: "64Mi", limit: "256Mi"
    env from: settings
    http_probe :readiness, port: :http, period_seconds: 5
  end

  # One replica per node, where there are replicas to spread.
  anti_affinity(on: "kubernetes.io/hostname") if production?
end

expose web, ports: {http: 80}
autoscale web, replicas: 3..8, cpu: 70 if production?
