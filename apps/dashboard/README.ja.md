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

### 本番での運用

本番ではsystemdサービスとして動かしてください。

```sh
cp deploy/rubernetes-dashboard.service /etc/systemd/system/
install -m 0600 deploy/rubernetes-dashboard.env /etc/rubernetes/dashboard.env   # コピー後に編集する
RAILS_ENV=production bin/rails assets:precompile
systemctl daemon-reload && systemctl enable --now rubernetes-dashboard
curl --noproxy '*' -sS http://<DASHBOARD_BIND>:3000/up
```

ユニットはPumaのworkerを1つに固定しています。時系列データの最新部分をcollectorのプロセスがメモリに持っているためです。

### クラスタ経由での公開

`deploy/ingress.yaml`を適用すると、ホストで動くダッシュボードをクラスタのingress controller経由で公開できます。マニフェストは次の3つを作ります。

- selectorのないService
- `DASHBOARD_BIND`を指すEndpointSlice
- cert-managerが発行した証明書を使うIngress

公開する前に、必ず`DASHBOARD_PASSWORD`を設定してください。UIからPodを削除できるためです。

## 設定

設定はすべて環境変数で行います。定義は`lib/dashboard/config.rb`にあります。

| 変数 | 既定値 | 意味 |
|---|---|---|
| `RUBERNETES_KUBECONFIG` | `<RUBERNETES_CLUSTER_ROOT>/kubeconfig` | クラスタの認証情報 |
| `RUBERNETES_CLUSTER_ROOT` | `/srv/rbn-app/linux-amd64-ipv4-native` | `cluster.json`とkubeconfigの置き場所 |
| `DASHBOARD_BIND` | `10.240.0.1`（systemdユニットの場合） | 待ち受けアドレス |
| `DASHBOARD_PASSWORD` | 空。認証なし | UIとAPIのHTTP basic認証のパスワード |
| `DASHBOARD_EXTERNAL_URL` | なし | 公開URL |
| `DASHBOARD_HOSTS` | なし | Railsが受け付けるHostヘッダ |
| `DASHBOARD_DATA_DIR` | `apps/dashboard/data` | ブロック、WAL、ラベルインデックスの保存先 |
| `DASHBOARD_SCRAPE_INTERVAL` | `15` | メトリクスを取得する間隔。単位は秒 |
| `DASHBOARD_SCRAPE_TIMEOUT` | `10` | 取得のタイムアウト。単位は秒 |
| `DASHBOARD_EVALUATION_INTERVAL` | 取得間隔と同じ | ルールを評価する間隔 |
| `DASHBOARD_RETENTION` | `15d` | 保持期間 |
| `DASHBOARD_BLOCK_RANGE` | `2h` | ブロックの長さ |
| `DASHBOARD_RULES` | `config/rules.yml` | ルールファイル |
| `DASHBOARD_ALERT_WEBHOOK` | 空 | Alertmanager互換の通知先 |
| `DASHBOARD_ALLOW_WRITES` | `1` | `0`にするとUIが読み取り専用になる |
| `DASHBOARD_COLLECTOR` | `1` | `0`にするとメトリクスを取得せず、UIだけが動く |

PodとServiceのメトリクスは、PodのIPに直接接続して取得します。HTTPプロキシを使う環境では、`no_proxy`を設定してPod宛ての通信がプロキシを通らないようにしてください。

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
