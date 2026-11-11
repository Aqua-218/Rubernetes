# frozen_string_literal: true

# The same stack for every tenant, sized per tenant.
#
# In YAML this is one copy per tenant, or a template language on top of YAML.
# Here it is a list and a loop.
#
#   rubectl render -f examples/manifests/tenants.rb --allow-code -o yaml

TENANTS = [
  {name: "acme", replicas: 3, pods: 40},
  {name: "globex", replicas: 1, pods: 10}
].freeze

def worker(tenant)
  deployment "worker", namespace: tenant[:name], labels: {"tenant" => tenant[:name]} do
    replicas tenant[:replicas]
    container "worker", image: "busybox:1.36", command: ["sh", "-c", "while true; do echo working for $TENANT; sleep 30; done"] do
      env "TENANT", tenant[:name]
      cpu request: "50m"
      memory request: "32Mi"
    end
    pod { termination_grace_period_seconds 5 }
  end
end

TENANTS.each do |tenant|
  namespace tenant[:name], labels: {"tenant" => tenant[:name]}

  resource_quota "tenant", namespace: tenant[:name] do
    hard pods: tenant[:pods].to_s
  end

  worker(tenant)
end
