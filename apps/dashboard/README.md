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

Samples go into `lib/tsdb`, a Prometheus-shaped store: Gorilla-compressed
chunks, a write-ahead log, 2-hour blocks, time-based retention and a SQLite
label index. `lib/promql` implements PromQL (instant and range selectors,
`offset` and `@`, subqueries, the aggregation and function set, vector
matching with `on`/`ignoring`/`group_left`/`group_right`, set operators).
`config/rules.yml` holds recording and alerting rules in the Prometheus
rule-file format; alerts move through pending/firing/resolved, produce
`ALERTS` series and can be posted to an Alertmanager-style webhook.

* Database creation

* Database initialization

* How to run the test suite

* Services (job queues, cache servers, search engines, etc.)

* Deployment instructions

* ...
