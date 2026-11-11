# frozen_string_literal: true

# A web application: its configuration, three replicas and a Service.
#
#   rubectl render -f examples/manifests/web.rb --allow-code -o yaml
#   rubectl render -f examples/manifests/web.rb --allow-code --env APP_ENV | kubectl apply -f -

def production? = ENV["APP_ENV"] == "production"

config_map "web-config" do
  data LOG_LEVEL: production? ? "info" : "debug", GREETING: "hello"
end

deployment "web" do
  replicas production? ? 3 : 1

  container "nginx", image: "nginx:1.27" do
    port 80
    cpu request: "100m", limit: "500m"
    memory request: "64Mi", limit: "256Mi"
    env from: configmap("web-config")
    readiness_probe http_get: {path: "/", port: 80}, period_seconds: 5
  end

  # One replica per node, where there are replicas to spread.
  anti_affinity(on: "kubernetes.io/hostname") if production?
end

service "web" do
  selector app: "web"
  ports [{port: 80, target_port: 80}]
end
