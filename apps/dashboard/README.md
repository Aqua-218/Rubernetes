# Rubernetes dashboard

A Rails 8 application that is both the cluster's web UI and its Prometheus.
It runs on the host (or anywhere with a kubeconfig), not inside the cluster,
so it keeps working while the cluster is unhealthy.

**Web UI.** Nodes, namespaces, workloads (Deployments, StatefulSets,
DaemonSets, Jobs, CronJobs, Services, Ingresses, ConfigMaps, …), Pods with
logs and YAML, events and alerts. Writes (delete Pod, scale, rollout
restart) can be switched off.

**Metrics server.** A collector thread in the same process discovers and
scrapes, every `DASHBOARD_SCRAPE_INTERVAL` seconds:

- every API server (`/metrics`),
- every node's kubelet endpoints (`/metrics`, `/metrics/cadvisor`,
  `/metrics/resource`, `/metrics/probes`),
- Pods and Services annotated `prometheus.io/scrape: "true"`
  (`prometheus.io/port`, `prometheus.io/path`, `prometheus.io/scheme`),
- a built-in kube-state exporter (`kube_node_*`, `kube_pod_*`,
  `kube_deployment_*`, …) computed from the API.

* Configuration

* Database creation

* Database initialization

* How to run the test suite

* Services (job queues, cache servers, search engines, etc.)

* Deployment instructions

* ...
