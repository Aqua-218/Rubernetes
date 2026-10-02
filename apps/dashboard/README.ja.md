# Rubernetesダッシュボード

[English](README.md) | 日本語

クラスタのWeb UIとPrometheusを兼ねるRails 8アプリケーションです。クラスタの中ではなくホスト上で動きます。kubeconfigがあればどこでも起動でき、クラスタの調子が悪いときにも使えます。

## 機能

### Web UI

次のものを閲覧できます。

- ノードとnamespace
- Deployment、StatefulSet、DaemonSet、Job、CronJob、Service、Ingress、ConfigMapなどのリソース
- Pod。ログとYAMLも見られます
- イベントとアラート

Podの削除、scale、rollout restartといった書き込み操作もできます。書き込み操作は設定で無効にできます。

### メトリクスの収集

同じプロセスの中でcollectorスレッドが動きます。collectorは`DASHBOARD_SCRAPE_INTERVAL`秒ごとに対象を探し、メトリクスを取得します。対象は次の4種類です。

- すべてのAPIサーバの`/metrics`
- すべてのノードのkubeletエンドポイント。`/metrics`、`/metrics/cadvisor`、`/metrics/resource`、`/metrics/probes`の4つ
- `prometheus.io/scrape: "true"`のアノテーションが付いたPodとService。`prometheus.io/port`、`prometheus.io/path`、`prometheus.io/scheme`で接続先を指定できます
- 内蔵のkube-stateエクスポータ。APIの内容から`kube_node_*`、`kube_pod_*`、`kube_deployment_*`などを算出します

### 時系列ストア

取得したサンプルは`lib/tsdb`のストアに保存します。構造はPrometheusと同じです。チャンクはGorilla方式で圧縮し、write-ahead logを持ち、2時間ごとにブロックへまとめます。古いデータは保持期間に従って削除します。ラベルのインデックスにはSQLiteを使っています。

### PromQL

`lib/promql`がPromQLを実装しています。対応している構文は次のとおりです。

- instantセレクタとrangeセレクタ
- `offset`と`@`
- サブクエリ
- 集約と関数
- `on`、`ignoring`、`group_left`、`group_right`によるベクトルマッチ
- 集合演算

### ルールとアラート

`config/rules.yml`にrecordingルールとalertingルールを書きます。形式はPrometheusのルールファイルと同じです。アラートはpending、firing、resolvedの順に遷移し、`ALERTS`系列を生成します。Alertmanager形式のwebhookに通知することもできます。

### HTTP API

HTTP APIはPrometheusと互換です。そのためGrafanaのPrometheusデータソースとして登録できます。

```
/api/v1/query  /api/v1/query_range  /api/v1/series  /api/v1/labels  /api/v1/label/:name/values
/api/v1/metadata  /api/v1/targets  /api/v1/rules  /api/v1/alerts  /api/v1/status/{buildinfo,tsdb,runtimeinfo,config}
```

### ページ

| パス | 内容 |
|---|---|
| `/graph` | 式ブラウザ |
| `/targets`、`/rules`、`/alerts`、`/status` | 各種の状態 |
| `/up` | ヘルスチェック |

## 起動

Ruby 3.4.11とクラスタのkubeconfigが必要です。何も指定しない場合は、`tools/conformance/cluster.rb`が`/srv/rbn-app/linux-amd64-ipv4-native`に作ったクラスタに接続します。

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
