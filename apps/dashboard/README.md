# Rubernetes dashboard

English | [日本語](README.ja.md)

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

The HTTP API is Prometheus-compatible, so Grafana can use the dashboard as a
Prometheus data source:

```
/api/v1/query  /api/v1/query_range  /api/v1/series  /api/v1/labels  /api/v1/label/:name/values
/api/v1/metadata  /api/v1/targets  /api/v1/rules  /api/v1/alerts  /api/v1/status/{buildinfo,tsdb,runtimeinfo,config}
```

`/graph` is the expression browser, `/targets`, `/rules`, `/alerts` and
`/status` the usual status pages, `/up` the health check.

## Running it

Ruby 3.4.11 and a kubeconfig for the cluster. The defaults point at a
cluster brought up by `tools/conformance/cluster.rb` under
`/srv/rbn-app/linux-amd64-ipv4-native`.

```sh
cd apps/dashboard
bundle install
RUBERNETES_KUBECONFIG=/path/to/kubeconfig bin/rails server -p 3000
```

Production, as a systemd service (the unit keeps Puma to one worker because
the time-series head lives in the collector's process):

```sh
cp deploy/rubernetes-dashboard.service /etc/systemd/system/
install -m 0600 deploy/rubernetes-dashboard.env /etc/rubernetes/dashboard.env   # then edit it
RAILS_ENV=production bin/rails assets:precompile
systemctl daemon-reload && systemctl enable --now rubernetes-dashboard
curl --noproxy '*' -sS http://<DASHBOARD_BIND>:3000/up
```

`deploy/ingress.yaml` publishes the host-run dashboard through the cluster's
ingress controller: a Service without selector, an EndpointSlice pointing at
`DASHBOARD_BIND`, and an Ingress with a cert-manager issued certificate. Set
`DASHBOARD_PASSWORD` before publishing it: the UI can delete Pods.

## Configuration

Everything is environment variables (`lib/dashboard/config.rb`):

| Variable | Default | Meaning |
|---|---|---|
| `RUBERNETES_KUBECONFIG` | `<RUBERNETES_CLUSTER_ROOT>/kubeconfig` | Cluster credentials |
| `RUBERNETES_CLUSTER_ROOT` | `/srv/rbn-app/linux-amd64-ipv4-native` | Where `cluster.json` and the kubeconfig live |
| `DASHBOARD_BIND` | `10.240.0.1` (systemd unit) | Listen address |
| `DASHBOARD_PASSWORD` | empty (no auth) | HTTP basic-auth password for UI and API |
| `DASHBOARD_EXTERNAL_URL`, `DASHBOARD_HOSTS` | | Public URL and the Host header values Rails accepts |
| `DASHBOARD_DATA_DIR` | `apps/dashboard/data` | Blocks, WAL and label index |
| `DASHBOARD_SCRAPE_INTERVAL`, `DASHBOARD_SCRAPE_TIMEOUT` | `15`, `10` | Seconds |
| `DASHBOARD_EVALUATION_INTERVAL` | scrape interval | Rule evaluation cadence |
| `DASHBOARD_RETENTION`, `DASHBOARD_BLOCK_RANGE` | `15d`, `2h` | Retention and block size |
| `DASHBOARD_RULES` | `config/rules.yml` | Rule file |
| `DASHBOARD_ALERT_WEBHOOK` | empty | Alertmanager-compatible receiver |
| `DASHBOARD_ALLOW_WRITES` | `1` | `0` makes the UI read-only |
| `DASHBOARD_COLLECTOR` | `1` | `0` disables scraping (UI only) |
| `no_proxy` | | Pod and Service scrapes dial Pod IPs; keep them off any HTTP proxy |

## Development

```sh
bin/rails test                     # 79 tests: PromQL engine, TSDB store, scraper, rules, API, pages
bin/rails console
```

`test/support/fake_cluster.rb` stands in for the API server, so the suite
runs without a cluster. The JSON gem is pinned to the Ruby 3.4.11 default
(`json 2.9.1`) for the same reason as the main Gemfile.

## Layout

| Path | Contents |
|---|---|
| `app/` | Controllers and views for the cluster browser and the Prometheus pages |
| `lib/dashboard/` | Configuration, the resource catalog (which kinds are browsable and how), runtime wiring that starts the collector with the web server |
| `lib/prom/` | Collector loop, target discovery, scraper, exposition parser, Gorilla chunk codec, kube-state exporter, rules |
| `lib/promql/` | Parser, engine and function set |
| `lib/tsdb/` | The store: head, WAL, blocks, retention, label index |
| `config/rules.yml` | Default recording and alerting rules |
| `deploy/` | systemd unit, environment file, Ingress manifest |
