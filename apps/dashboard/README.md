# Rubernetes dashboard

English | [日本語](README.ja.md)

A Rails 8 application that serves as both the cluster's web UI and its
Prometheus. It runs on the host, not inside the cluster. It starts anywhere
a kubeconfig is available and keeps working while the cluster is unhealthy.

## Features

### Web UI

You can browse:

- nodes and namespaces
- Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Services,
  Ingresses, ConfigMaps and other resources
- Pods, with their logs and YAML
- events and alerts

The UI can also write: delete a Pod, scale, and restart a rollout. Writes
can be turned off in the configuration.

### Metrics collection

A collector thread runs in the same process. Every
`DASHBOARD_SCRAPE_INTERVAL` seconds it discovers targets and scrapes them.
There are four kinds of target:

- `/metrics` of every API server
- the kubelet endpoints of every node: `/metrics`, `/metrics/cadvisor`,
  `/metrics/resource` and `/metrics/probes`
- Pods and Services annotated with `prometheus.io/scrape: "true"`. Use
  `prometheus.io/port`, `prometheus.io/path` and `prometheus.io/scheme` to
  say where to connect
- a built-in kube-state exporter, which computes `kube_node_*`,
  `kube_pod_*`, `kube_deployment_*` and similar metrics from the API

### Time-series store

Samples are stored by `lib/tsdb`, which is structured like Prometheus.
Chunks are Gorilla-compressed, there is a write-ahead log, and samples are
compacted into 2-hour blocks. Old data is deleted according to the retention
period. The label index uses SQLite.

### PromQL

`lib/promql` implements PromQL. It supports:

- instant and range selectors
- `offset` and `@`
- subqueries
- aggregations and functions
- vector matching with `on`, `ignoring`, `group_left` and `group_right`
- set operators

### Rules and alerts

Write recording and alerting rules in `config/rules.yml`, in the Prometheus
rule-file format. An alert moves through pending, firing and resolved, and
produces `ALERTS` series. Alerts can also be sent to an Alertmanager-style
webhook.

### HTTP API

The HTTP API is compatible with Prometheus, so Grafana can register the
dashboard as a Prometheus data source.

```
/api/v1/query  /api/v1/query_range  /api/v1/series  /api/v1/labels  /api/v1/label/:name/values
/api/v1/metadata  /api/v1/targets  /api/v1/rules  /api/v1/alerts  /api/v1/status/{buildinfo,tsdb,runtimeinfo,config}
```

### Pages

| Path | Contents |
|---|---|
| `/graph` | The expression browser |
| `/targets`, `/rules`, `/alerts`, `/status` | Status pages |
| `/up` | The health check |

## Running it

You need Ruby 3.4.11 and a kubeconfig for the cluster. With nothing
specified, the dashboard connects to the cluster that
`tools/conformance/cluster.rb` created under
`/srv/rbn-app/linux-amd64-ipv4-native`.

```sh
cd apps/dashboard
bundle install
RUBERNETES_KUBECONFIG=/path/to/kubeconfig bin/rails server -p 3000
```

### In production

Run it as a systemd service.

```sh
cp deploy/rubernetes-dashboard.service /etc/systemd/system/
install -m 0600 deploy/rubernetes-dashboard.env /etc/rubernetes/dashboard.env   # edit it after copying
RAILS_ENV=production bin/rails assets:precompile
systemctl daemon-reload && systemctl enable --now rubernetes-dashboard
curl --noproxy '*' -sS http://<DASHBOARD_BIND>:3000/up
```

The unit fixes Puma at one worker, because the collector's process holds the
newest part of the time-series data in memory.

### Publishing through the cluster

Applying `deploy/ingress.yaml` publishes the host-run dashboard through the
cluster's ingress controller. The manifest creates:

- a Service without a selector
- an EndpointSlice pointing at `DASHBOARD_BIND`
- an Ingress that uses a certificate issued by cert-manager

Always set `DASHBOARD_PASSWORD` before publishing, because the UI can delete
Pods.

## Configuration

All configuration is through environment variables, defined in
`lib/dashboard/config.rb`.

| Variable | Default | Meaning |
|---|---|---|
| `RUBERNETES_KUBECONFIG` | `<RUBERNETES_CLUSTER_ROOT>/kubeconfig` | Cluster credentials |
| `RUBERNETES_CLUSTER_ROOT` | `/srv/rbn-app/linux-amd64-ipv4-native` | Where `cluster.json` and the kubeconfig are |
| `DASHBOARD_BIND` | `10.240.0.1` (in the systemd unit) | Listen address |
| `DASHBOARD_PASSWORD` | empty: no authentication | HTTP basic-auth password for the UI and the API |
| `DASHBOARD_EXTERNAL_URL` | none | Public URL |
| `DASHBOARD_HOSTS` | none | Host header values Rails accepts |
| `DASHBOARD_DATA_DIR` | `apps/dashboard/data` | Where blocks, the WAL and the label index are stored |
| `DASHBOARD_SCRAPE_INTERVAL` | `15` | Scrape interval, in seconds |
| `DASHBOARD_SCRAPE_TIMEOUT` | `10` | Scrape timeout, in seconds |
| `DASHBOARD_EVALUATION_INTERVAL` | same as the scrape interval | Rule evaluation interval |
| `DASHBOARD_RETENTION` | `15d` | Retention period |
| `DASHBOARD_BLOCK_RANGE` | `2h` | Block length |
| `DASHBOARD_RULES` | `config/rules.yml` | Rule file |
| `DASHBOARD_ALERT_WEBHOOK` | empty | Alertmanager-compatible receiver |
| `DASHBOARD_ALLOW_WRITES` | `1` | `0` makes the UI read-only |
| `DASHBOARD_COLLECTOR` | `1` | `0` disables scraping, leaving only the UI |

Pod and Service metrics are scraped by connecting directly to Pod IPs. Where
an HTTP proxy is in use, set `no_proxy` so that traffic to Pods does not go
through the proxy.

## Development

```sh
bin/rails test                     # 79 tests: PromQL engine, TSDB, scraper, rules, API, pages
bin/rails console
```

The tests run without a cluster. `test/support/fake_cluster.rb` stands in
for the API server.

Two gem versions are pinned: the json gem to `json 2.9.1`, which ships with
Ruby 3.4.11, and minitest to the 5.25 series. The main project's tests run
without bundler, so they would load any newer gem that the dashboard's
bundle installs.

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
