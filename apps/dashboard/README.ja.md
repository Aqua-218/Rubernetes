# Rubernetes ダッシュボード

[English](README.md) | 日本語

クラスタの Web UI と Prometheus を兼ねる Rails 8 アプリケーションです。
クラスタの中ではなくホスト上（kubeconfig があればどこでも）で動くので、
クラスタが不調なときも使えます。

**Web UI。** ノード、namespace、ワークロード（Deployment、StatefulSet、
DaemonSet、Job、CronJob、Service、Ingress、ConfigMap など）、ログと YAML
付きの Pod、イベント、アラート。書き込み操作（Pod 削除、scale、rollout
restart）は無効化できます。

**メトリクスサーバ。** 同じプロセス内の collector スレッドが
`DASHBOARD_SCRAPE_INTERVAL` 秒ごとに次を発見・scrape します。

- すべての API サーバ（`/metrics`）
- すべてのノードの kubelet エンドポイント（`/metrics`、`/metrics/cadvisor`、
  `/metrics/resource`、`/metrics/probes`）
- `prometheus.io/scrape: "true"` を付けた Pod と Service
  （`prometheus.io/port`、`prometheus.io/path`、`prometheus.io/scheme`）
- API から算出する内蔵 kube-state エクスポータ（`kube_node_*`、`kube_pod_*`、
  `kube_deployment_*` など）

サンプルは Prometheus 型のストア `lib/tsdb` に入ります: Gorilla 圧縮チャンク、
write-ahead log、2 時間ブロック、時間ベースの保持期間、SQLite のラベル
インデックス。`lib/promql` は PromQL を実装します（instant / range セレクタ、
`offset` と `@`、サブクエリ、集約と関数一式、`on`/`ignoring`/`group_left`/
`group_right` のベクトルマッチ、集合演算）。`config/rules.yml` は Prometheus の
ルールファイル形式で recording / alerting ルールを持ち、アラートは pending →
firing → resolved と遷移して `ALERTS` 系列を生成し、Alertmanager 形式の
webhook に通知できます。

HTTP API は Prometheus 互換なので、Grafana の Prometheus データソースとして
使えます。

```
/api/v1/query  /api/v1/query_range  /api/v1/series  /api/v1/labels  /api/v1/label/:name/values
/api/v1/metadata  /api/v1/targets  /api/v1/rules  /api/v1/alerts  /api/v1/status/{buildinfo,tsdb,runtimeinfo,config}
```

`/graph` が式ブラウザ、`/targets`、`/rules`、`/alerts`、`/status` が各種
状態ページ、`/up` がヘルスチェックです。

## 起動

Ruby 3.4.11 とクラスタの kubeconfig が必要です。既定値は
`tools/conformance/cluster.rb` が `/srv/rbn-app/linux-amd64-ipv4-native` に
作ったクラスタを指します。

```sh
cd apps/dashboard
bundle install
RUBERNETES_KUBECONFIG=/path/to/kubeconfig bin/rails server -p 3000
```

本番は systemd サービスとして動かします（時系列の head が collector の
プロセスにあるため、ユニットは Puma を 1 worker に固定しています）。

```sh
cp deploy/rubernetes-dashboard.service /etc/systemd/system/
install -m 0600 deploy/rubernetes-dashboard.env /etc/rubernetes/dashboard.env   # その後編集
RAILS_ENV=production bin/rails assets:precompile
systemctl daemon-reload && systemctl enable --now rubernetes-dashboard
curl --noproxy '*' -sS http://<DASHBOARD_BIND>:3000/up
```

`deploy/ingress.yaml` はホストで動くダッシュボードをクラスタの ingress
controller 経由で公開します: selector 無しの Service、`DASHBOARD_BIND` を指す
EndpointSlice、cert-manager 発行の証明書を持つ Ingress。公開前に必ず
`DASHBOARD_PASSWORD` を設定してください。UI から Pod を削除できます。

## 設定

すべて環境変数です（`lib/dashboard/config.rb`）。

| 変数 | 既定値 | 意味 |
|---|---|---|
| `RUBERNETES_KUBECONFIG` | `<RUBERNETES_CLUSTER_ROOT>/kubeconfig` | クラスタの認証情報 |
| `RUBERNETES_CLUSTER_ROOT` | `/srv/rbn-app/linux-amd64-ipv4-native` | `cluster.json` と kubeconfig の置き場所 |
| `DASHBOARD_BIND` | `10.240.0.1`（systemd ユニット） | 待ち受けアドレス |
| `DASHBOARD_PASSWORD` | 空（認証なし） | UI と API の HTTP basic 認証パスワード |
| `DASHBOARD_EXTERNAL_URL`、`DASHBOARD_HOSTS` | | 公開 URL と Rails が受け付ける Host ヘッダ |
| `DASHBOARD_DATA_DIR` | `apps/dashboard/data` | ブロック、WAL、ラベルインデックス |
| `DASHBOARD_SCRAPE_INTERVAL`、`DASHBOARD_SCRAPE_TIMEOUT` | `15`、`10` | 秒 |
| `DASHBOARD_EVALUATION_INTERVAL` | scrape 間隔 | ルール評価の周期 |
| `DASHBOARD_RETENTION`、`DASHBOARD_BLOCK_RANGE` | `15d`、`2h` | 保持期間とブロック長 |
| `DASHBOARD_RULES` | `config/rules.yml` | ルールファイル |
| `DASHBOARD_ALERT_WEBHOOK` | 空 | Alertmanager 互換の受信先 |
| `DASHBOARD_ALLOW_WRITES` | `1` | `0` で UI を読み取り専用に |
| `DASHBOARD_COLLECTOR` | `1` | `0` で scrape を無効化（UI のみ） |
| `no_proxy` | | Pod/Service の scrape は Pod IP に直接つなぐ。HTTP プロキシを通さないこと |

## 開発

```sh
bin/rails test                     # 79 テスト: PromQL エンジン、TSDB、scraper、ルール、API、ページ
bin/rails console
```

`test/support/fake_cluster.rb` が API サーバの代役なので、スイートはクラスタ
無しで動きます。json gem はメインの Gemfile と同じ理由で Ruby 3.4.11 既定の
`json 2.9.1` に、minitest は 5.25 系に固定しています（dashboard の bundle が
入れた新しい gem を、bundler を通さない本体のテストが拾ってしまうため）。

## 構成

| パス | 内容 |
|---|---|
| `app/` | クラスタブラウザと Prometheus 系ページのコントローラとビュー |
| `lib/dashboard/` | 設定、リソースカタログ（どの kind をどう閲覧できるか）、Web サーバと一緒に collector を起動する配線 |
| `lib/prom/` | collector ループ、ターゲット発見、scraper、exposition パーサ、Gorilla チャンク、kube-state エクスポータ、ルール |
| `lib/promql/` | パーサ、エンジン、関数群 |
| `lib/tsdb/` | ストア: head、WAL、ブロック、保持期間、ラベルインデックス |
| `config/rules.yml` | 既定の recording / alerting ルール |
| `deploy/` | systemd ユニット、環境ファイル、Ingress マニフェスト |
