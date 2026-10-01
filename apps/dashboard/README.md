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

* System dependencies

* Configuration

* Database creation

* Database initialization

* How to run the test suite

* Services (job queues, cache servers, search engines, etc.)

* Deployment instructions

* ...
