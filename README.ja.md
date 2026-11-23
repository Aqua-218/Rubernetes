# Rubernetes

[English](README.md) | 日本語

RubernetesはKubernetes v1.36.2をRubyで実装し直したものです。Linux上で動きます。本物の`kubectl`やHelm、client-go、upstreamのchartを、手を加えずにそのまま使えます。

クラスタを構成するプログラムはすべてこのリポジトリのRubyコードです。APIサーバ、Raftデータストア、コントローラ、スケジューラ、ノードエージェント、コンテナランタイム、Podネットワーク、サービスプロキシ、クラスタDNS、ボリュームを自前で持っています。

Kubernetes本体との関係は次の3点です。

- クラスタの中でKubernetes由来のプログラムは動きません。
- Kubernetesのバイナリとイメージは、挙動を比べるテストの基準としてだけ使います。バージョンは固定しています。
- APIスキーマはupstreamから取り込みました。server-side apply、CELの型検査、DRAアロケータ、device cgroupフィルタなど一部のアルゴリズムは、upstreamのGoコードをRubyへ移植したものです。移植元とライセンスは[`NOTICE`](NOTICE)にまとめてあります。

| 項目 | 内容 |
|---|---|
| 互換対象 | Kubernetes v1.36.2 |
| 公式Conformance | v1.36.2 の対象446件中446件合格（2026-11-18 UTC、IPv4 native プロファイル） |
| 対象環境 | Linux x86_64、cgroup v2、root権限、Ruby 3.4.11 |
| 規模 | `lib/`と`ext/`のRubyとCが約22万行、テストが約10万行 |
| ライセンス | Apache-2.0 |

Conformanceは、公式の`registry.k8s.io/conformance`イメージを改変せずにHydrophoneで実行した結果です。プロファイル名は`linux-amd64-ipv4-native`です。

このREADMEは使い方の入口です。仕様と設計は[`spec/`](spec/README.md)に書いてあります。

## 構成要素

実行ファイルは6つあり、ほかにダッシュボードが付属します。

| 実行ファイル | Kubernetesで相当するもの |
|---|---|
| `rubernetes-apiserver` | kube-apiserverとetcd |
| `rubernetes-controller-manager` | kube-controller-manager |
| `rubernetes-scheduler` | kube-scheduler |
| `rubernetes-agent` | kubelet、CRIランタイム、CNI |
| `rubernetes-proxy` | kube-proxy |
| `rubectl` | kubectlの一部 |
| `apps/dashboard` | Kubernetes dashboardとPrometheus |

実行時に必要なものはRubyと小さなCの拡張だけです。forkするRuby VMからは安全に呼べないシステムコールがあり、その呼び出しを[`ext/rubernetes_linux`](ext/README.ja.md)が受け持ちます。

### rubernetes-apiserver

v1.36.2が既定で提供するAPIとdiscoveryをすべて備えています。対応している機能は次のとおりです。

- JSON、YAML、Protobufでの入出力
- watch、patch、field manager付きのserver-side apply
- admissionプラグイン、webhook、CELポリシー
- 認証と認可、API Priority and Fairness、監査、保存時の暗号化
- CRDとAPI aggregation
- feature gateと`--runtime-config`

データは内蔵のRaftデータストアに保存します。コードは`lib/rubernetes/consensus/`にあります。CRC-32C付きのWAL、スナップショット、joint consensus、pre-vote、ReadIndex、相互TLSを実装しました。

### rubernetes-controller-manager

upstreamと同じコントローラ一式を動かします。ワークロード、GC、namespace、EndpointsとEndpointSlice、ServiceAccountとトークン、nodeのライフサイクル、CSRの承認、PVとPVC、quotaなどです。informerとwork queueの枠組みの上で動き、リーダー選出にも対応しています。

### rubernetes-scheduler

スケジューリングフレームワークと既定のプラグイン一式を実装しています。preemption、非同期のbind、scoringが使えます。

### rubernetes-agent

kubeletの役割を担います。Podの同期、probe、eviction、ノードのgraceful shutdown、device plugin、CPU・メモリ・topologyの各manager、DRAを実装しています。`exec`、`logs`、`/metrics`、`/configz`などのkubelet APIも提供します。

コンテナランタイムは3種類から選べます。

- native: clone3、cgroup v2、namespaceを直接使います。OCIイメージの取得と検証もRubyで行います。Zstandard圧縮のレイヤー展開にはホストの`libzstd.so.1`を使います。
- microvm: jailer付きのFirecrackerでPodを動かします。rootfsはdm-verityで検証し、vsock経由のsupervisorが中で動きます。
- CRI: 外部のCRIランタイムにつなぎます。明示的に有効にしたときだけ使われます。

Podネットワークは内蔵のbridgeデータパスです。dual-stackのIPAM、NetworkPolicy、egress NAT、クラスタDNSを持っています。NetworkPolicyはnftablesかeBPFで実現します。

### rubernetes-proxy

Service、EndpointSlice、NodePort、session affinity、traffic policyを処理します。データパスはiptables、nftables、eBPFの3種類です。チェーンの構成とメトリクスはupstreamに合わせました。

### rubectl

`get`、`create`、`apply`、`patch`、`delete`、`watch`、`logs`、`raw`が使えます。スキーマから生成したRubyのManifest DSLも読み込めます。本物の`kubectl`を使ってもかまいません。

`rubectl logs web-0 -n production -c app --tail 100 -f` でコンテナのログを追従できます。`-p` で前回のコンテナ、`--timestamps` でログのタイムスタンプを表示します。取得範囲は `--since 10m` または `--since-time 2026-11-20T10:00:00Z` で指定できます。`-c` を省略すると、Pod の `kubectl.kubernetes.io/default-container` アノテーションか、最初のコンテナを選びます。接続には現在の kubeconfig を使い、`pods` と `pods/log` の `get` 権限が必要です。

`rubectl disk web-0 -n production` は、Pod の一時ストレージ使用量、コンテナごとの書き込み層とログ、ボリュームの使用量を表示します。合計は kubelet が報告した値です。内訳の行には合計に含まれる値もあります。RAM と PVC は区別して表示し、種類を判定できないボリュームは不明と表示します。

`emptyDir` に正の `sizeLimit` を指定した場合は、その上限を使用量の横にバイト単位で表示します。JSON のフィールド名は `sizeLimitBytes` です。使用量がまだ未計測でも、指定した上限を確認できます。

`-o json` を付けると、`ephemeralStorageUsedBytes`、`containers`、`volumes` にバイト数を出力します。未計測の値は JSON では `null`、テキストでは `unknown` と表示します。`status` は計測あり（`sampled`）、未配置（`notScheduled`）、Pod UID なし（`missingUID`）、同じ UID の計測なし（`noSample`）のいずれかです。現在の kubeconfig を使い、Pod とノードの `nodes/proxy` サブリソースへの `get` 権限が必要です。

`rubectl disk -n production` は、名前空間内の Pod を一時ストレージ使用量の多い順に表示します。未計測の Pod は末尾に並びます。クラスタ全体で容量を使っている Pod を探すには `rubectl disk -A` を使います。`--node worker-1` で 1 ノードに絞れます。一覧では Pod の `list` 権限を使い、対象ノードごとの集計を 1 回ずつ取得します。`-o json` では、`pods` に Pod の識別情報、ノード名、状態、使用量の合計（バイト）を順に出力します。

`rubectl disk node/worker-1` は、ノードのルート、ランタイムのイメージ、コンテナの各ファイルシステムについて、使用量、空き容量、総容量をバイト単位で表示します。複数の項目が同じファイルシステムを指すことがあるため、計測値は項目ごとに表示します。指定ノードの集計を 1 回取得し、`nodes/proxy` への `get` 権限が必要です。`-o json` では、`filesystems` 内の `fs`、`imageFs`、`containerFs` にそれぞれ `usedBytes`、`availableBytes`、`capacityBytes` を出力します。未計測の値は JSON では `null`、テキストでは `unknown` と表示します。

### apps/dashboard

Railsで書いたダッシュボードです。クラスタの中身を閲覧でき、Prometheus形式の時系列ストアを自前で持っています。PromQL、recordingルール、alertingルール、Prometheus互換のHTTP APIに対応しています。詳しくは[ダッシュボードのREADME](apps/dashboard/README.ja.md)を読んでください。

## クイックスタート

次のものを用意してください。

- cgroup v2が有効なLinux x86_64とroot権限
- `nft`と`iptables`
- Ruby 3.4.11（Gemfileで固定しています）
- イメージを取得するための外向き通信
- kubectl v1.36.2。クラスタを立てるだけなら不要です

kubectlのチェックサムは`test/compatibility/clients/matrix.yml`に書いてあります。KVMは`microvm` RuntimeClassを使うときだけ必要です。

```sh
git clone <this repository> && cd 2026
bundle install
rake abi:compile                    # Cの拡張をbuild/配下にビルド

# クラスタを作る。control 1ノードとworker 1ノードで、10秒ほどで使えるようになる
sudo ruby -Ilib exe/rubectl cluster up

export KUBECONFIG=/var/lib/rubernetes/clusters/default/kubeconfig
kubectl get nodes
kubectl create deployment web --image=nginx --replicas=3
kubectl expose deployment web --port=80 --type=NodePort
kubectl get pods -o wide

sudo ruby -Ilib exe/rubectl cluster status
sudo ruby -Ilib exe/rubectl cluster down     # プロセスを止める。状態はディスクに残る
sudo ruby -Ilib exe/rubectl cluster start    # 同じ状態で起動し直す。ホストの再起動後もこれで戻る
sudo ruby -Ilib exe/rubectl cluster scale --controls 3   # 動かしたままcontrolノードを3台にする
```

`rubectl cluster up`は1台のホスト上にクラスタを作ります。PKI、Raftデータストア、クラスタDNS、kubeconfigも同時に用意します。状態は`/var/lib/rubernetes/clusters/<name>`に置き、起動したプロセス、ポート、ファイルの一覧は同じ場所の`cluster.json`で確認できます。

| オプション | 意味 |
|---|---|
| `--ha` | control 3ノードとworker 3ノードにする。Raftは3台で合意を取る |
| `--controls N`、`--workers N` | ノード数を個別に決める |
| `--ip-family ipv4\|ipv6\|dual` | Podとサービスのアドレスファミリ |
| `--identities components` | 各コンポーネントにkubeadmと同じidentityを与える |
| `--name NAME`、`--root DIR` | クラスタの名前と置き場所 |
| `--no-storage` | 既定のStorageClassとhostPathプロビジョナーを入れない |

`scale`は、Raftのjoint consensusでデータストアの構成を変えます。変更の間もクラスタは使い続けられ、3台になったあとは1台を失っても動き続けます。`--controls`に今より小さい数を渡すと、新しい順にcontrolノードを外します。外すノードがリーダーなら先に残るノードへ引き継ぎ、そのノードを使っていたコンポーネントは残るノードへ向け直して再起動します。

既定では、`standard`というStorageClassが入ります。PersistentVolumeClaimを作ると、kube-controller-managerの`--enable-hostpath-provisioner`と同じ方式で、ホスト上のディレクトリがボリュームとして割り当てられます。

Conformanceの実行に使う`tools/conformance/cluster.rb`も同じコード（`lib/rubernetes/cluster/`）を呼んでいます。違いは構成を3+3に固定することだけです。

### 共用ホストで動かすときの注意

`up`は起動前に次のものを消します。

- `/sys/fs/cgroup/rubernetes`配下で動いているワークロード
- 同じネットワーク名前空間にある古い`rbn*`ブリッジと`rbn-*`名前空間

同じネットワーク名前空間で別のクラスタが動いている場合、`up`は起動を拒否します。クラスタのものではないファイルが入ったディレクトリを`--root`に指定した場合も拒否します。1台で複数のクラスタを動かすときは、`tools/conformance/netns_env.sh`でクラスタごとにネットワーク名前空間を分けてください。手順は[tools/conformance/README.ja.md](tools/conformance/README.ja.md)にあります。

### 常設インストール

リリース成果物から常設のクラスタを作る手順は[deploy/cluster/README.md](deploy/cluster/README.md)にあります。systemdユニット、PKI、アップグレード、バックアップとリストアを扱っています。

各デーモンは `--config` で指定した YAML を起動時に読みます。設定値を環境変数で上書きすることはありません。ノードエージェントには `--kubelet-config` で対応する Kubernetes v1beta1 の設定を追加できます。`--check-config` は起動時と同じ入力を検証します。既定値は `config/defaults/` にあります。 [ノードの設定ファイル](spec/node/node-agent.md)

### ダッシュボードとメトリクス

```sh
cd apps/dashboard && bundle install
RUBERNETES_KUBECONFIG=$KUBECONFIG bin/rails server -p 3000
```

起動したら`http://localhost:3000`を開いてください。ダッシュボードはすべてのAPIサーバとkubelet、それにアノテーションの付いたPodとServiceからメトリクスを集めて自前のストアに保存します。`/api/v1/query`などのPrometheus互換APIがあるので、GrafanaのPrometheusデータソースとしても使えます。

## Rubyで書く拡張

クラスタの振る舞いを、Rubyファイル1枚で書き足せます。ファイルはAPIに保存され、動いているコンポーネントがそのまま読み込みます。再ビルドも再起動も要りません。

| 足したいもの | Kubernetesでの方法 | Rubernetesでの方法 |
|---|---|---|
| スケジューラのFilterとScore | Goで書き、kube-schedulerを再ビルドして入れ替える | `filter`と`score`のブロック |
| admissionの検証と書き換え | webhookサーバをTLS証明書とともにデプロイする | `validate`と`mutate`のブロック |
| コントローラ | オペレータをイメージにしてデプロイする | `controller`のブロック |

次のファイルは、Podに`team`ラベルを必須にし、バッチ処理を対話用のノードから外します。

```ruby
# team_rules.rb
validate "pods", on: :create do |request|
  owner = request.object.dig("metadata", "labels", "team")
  request.reject("Pods need a `team` label so we know whom to ask") if owner.to_s.empty?
end

filter "KeepBatchOffInteractive" do |pod, node|
  next true unless pod.labels["tier"] == "batch"

  node.labels["workload"] == "interactive" ? "node is reserved for interactive workloads" : true
end
```

```sh
sudo ruby -Ilib exe/rubectl cluster up --workers 3 --extensions
export KUBECONFIG=/var/lib/rubernetes/clusters/default/kubeconfig

ruby -Ilib exe/rubectl extension apply team_rules.rb
# team-rules: filter:KeepBatchOffInteractive  validate:pods
#   scheduler   loaded
#   admission   loaded
#   controller  loaded

kubectl run web --image=nginx
# Error from server (Forbidden): extension team-rules denied the request:
# Pods need a `team` label so we know whom to ask
```

フィルタが返した理由は、`kubectl describe pod`のスケジューリング失敗のメッセージにそのまま出ます。ファイルを直して`apply`し直すと、次のPodから新しい版が使われます。構文エラーのあるファイルは、行番号を付けて手元で拒否されます。

配置ルールを編集したら、適用する前に手元で試せます。たとえば次のコマンドは、指定した Pod に対してファイル内の Ruby の `filter` と `score` を実行します。各ノードの加点、除外理由、該当ブロックのファイルと行番号が表示されます。

```sh
rubectl extension preview examples/extensions/team_rules.rb default/crunch
```

同じ条件で繰り返し試すには、Pod と Node を一度保存します。以降はクラスタへの接続も拡張のインストールも不要です。

```sh
kubectl get pods,nodes -A -o json > cluster.json
rubectl extension preview examples/extensions/team_rules.rb default/crunch cluster.json
```

編集前のファイルを `before.rb` に保存しておけば、採否・除外理由・採点の変化をノードごとに比較できます。合計点が同じでも、内訳が変われば、どの Ruby ブロックの点数や重みが変わったかを行番号付きで表示します。

```sh
rubectl extension diff before.rb examples/extensions/team_rules.rb default/crunch cluster.json
```

プレビューは指定ファイルの配置ルールだけを評価します。稼働中の Pod も未配置の状態として扱い、その Pod 自身を各ノードの使用量から除きます。Ruby ファイルは手元のユーザー権限で実行するため、自分が信頼するファイルを指定してください。

`rubectl extension list`で、各コンポーネントの読み込み結果と、ブロックが例外を出した回数を確認できます。Extensionは`kubectl get extensions.rubernetes.io`でも見えます。

Extensionのコードは、スケジューラ、APIサーバ、コントローラマネージャのプロセスの中で、その権限で動きます。隔離はしません。Extensionを書ける利用者はcluster-adminと同等に扱ってください。既定では無効で、`--extensions`を付けたクラスタ、または設定に`extensions: {enabled: true}`を書いたコンポーネントだけが読み込みます。

例は[examples/extensions/](examples/extensions/README.ja.md)に、仕様は[spec/ruby/extensions.md](spec/ruby/extensions.md)にあります。

## 動いているクラスタの中を見る

コンポーネントはRubyのプロセスなので、止めずに中を調べられます。`rubectl cluster up`で作ったクラスタでは、3つのコマンドが使えます。どれもクラスタのホスト上で、rootで実行します。

`rubectl why`は、スケジューラがPodをどう判断したかを表示します。どのプラグインがどのノードを外し、残ったノードに各プラグインが何点を付けたかが分かります。kube-schedulerでは、verbosityを上げて再起動しないと見えない情報です。

```sh
sudo ruby -Ilib exe/rubectl why crunch
# default/crunch: scheduled on worker-2  (attempt 1, 29.71 ms, 2026-11-11T15:34:20.272Z)
#   worker-2    599  TaintToleration 100x3  NodeResourcesFit 99  team-rules.PreferQuietNodes 100x2
#   worker-1    579  TaintToleration 100x3  NodeResourcesFit 99  team-rules.PreferQuietNodes 90x2
#   worker-0      -  team-rules.KeepBatchOffInteractive: node is reserved for interactive workloads
```

`rubectl console`は、動いているコンポーネントの中でRubyのプロンプトを開きます。`help`で、手の届くものの一覧が出ます。

```sh
sudo ruby -Ilib exe/rubectl console scheduler
# rubernetes-scheduler (pid 2641363, Ruby 3.4.11) -- `help` lists what is in reach, `exit` leaves
# scheduler> nodes.map { |node| [node.name, node.pods.length] }
# => [["worker-0", 2], ["worker-1", 2], ["worker-2", 3]]
# scheduler> queue
# => #<Rubernetes::Scheduler::SchedulingQueue @capacity @mutex @sequence @pending @unschedulable ...>
# scheduler> ivar(queue, :unschedulable).length
# => 1
```

`rubectl trace`は、メソッド1つの呼び出しを、引数、戻り値、所要時間とともに流します。ログを足して再ビルドする必要はありません。観測を終えると、取り付けたTracePointは外れます。

```sh
sudo ruby -Ilib exe/rubectl trace scheduler "Rubernetes::Scheduler::Framework#schedule" --seconds 30
# 15:37:00.558    78.220 ms  pod=#<Rubernetes::Scheduler::Pod default/t-86d6fc64db-r2sz2> nodes=[3 items] ...  => #<Rubernetes::Scheduler::ScheduleResult scheduled>
```

コンソールは、各プロセスが持つUnixソケットで待ち受けます。ソケットはrootだけが開けます。つないだ利用者はプロセスの中身をすべて読み書きできるので、その権限はデバッガを接続できる権限と同じです。仕様は[spec/ruby/console.md](spec/ruby/console.md)にあります。

## マニフェストをRubyで書く

マニフェストもRubyで書けます。出力は標準のKubernetesオブジェクトなので、本物の`kubectl`にそのまま渡せます。

```ruby
# web.rb
settings = config_map("web-config") { data LOG_LEVEL: "info" }

web = deployment "web" do
  rollout_on settings
  replicas 3

  container "nginx", image: "nginx:1.27" do
    port 80, name: "http"
    cpu request: "100m", limit: "500m"
    ephemeral_storage request: "32Mi", limit: "128Mi"
    env from: settings
    env_field "POD_IP", "status.podIP"
    env_resource "CPU_MILLICORES", "requests.cpu", divisor: "1m"
    http_probe :readiness, port: :http, period_seconds: 5
  end
end

frontend = expose web, ports: {http: 80}
ingress_for frontend, host: "web.example.test", port: :http, class_name: "nginx"
```

`check` に渡した Ruby のブロックは、そのファイルの宣言がそろってから、クラスタに接続する前に実行されます。たとえば本番環境の Deployment にチーム名を必須にできます。条件が偽なら `render`、`plan`、`apply` は宣言行と理由を表示して終了します。

```ruby
check "本番の Deployment に team ラベルが必要" do |resources|
  resources.select { |r| r["kind"] == "Deployment" && r.dig("metadata", "namespace") == "prod" }
           .all? { |r| !r.dig("metadata", "labels", "team").to_s.empty? }
end
```

`http_probe` の `port: :http` は、同じコンテナに宣言した TCP ポートを指します。名前を間違えると `rubectl render` が Ruby の行番号と使える名前を表示します。ポートを後の行に宣言しても解決できます。

Pod のラベルは `env_field "TEAM", label: "example.com/team"`、注釈は `env_field "REVISION", annotation: "example.com/revision"` で環境変数として渡せます。値はコンテナの起動時に決まります。

`env_resource "CPU_MILLICORES", "requests.cpu", divisor: "1m"` では、このコンテナの CPU 要求をミリコア単位で環境変数に設定します。`container: "worker"` を追加すると、同じ Pod の通常コンテナ、init コンテナ、サイドカーを参照できます。後から宣言したコンテナも参照できます。`divisor` を省略すると Kubernetes の既定値 `1` が使われます。

仮想ホストで応答するアプリは `http_probe :readiness, port: :http, path: "/ready", headers: {Host: "catalog.example.test"}` と書けます。接続先は Pod のまま、指定した Host で確認します。同名のヘッダーを複数送る場合は値を配列で渡せます。

データベースの起動待ちには `tcp_probe :startup, port: :sql`、gRPC のサービスには `grpc_probe :readiness, port: 9000, service: "catalog"` を使えます。コンテナ内でコマンドを実行する場合は `exec_probe :liveness, command: ["pg_isready", "-q"]` のように引数を配列で渡します。

`settings` のデータを変えて再適用すると、Deployment が新しい環境変数を持つ Pod に順次置き換えます。ConfigMap のラベルだけを編集した場合は稼働中の Pod を維持します。`env from: settings` には Ruby の宣言をそのまま渡せます。

コンテナ内で `mount settings, at: "/etc/app"` と書くと、ConfigMap をファイルとして読み取れます。Pod のボリュームと読み取り専用マウントを生成し、複数のコンテナで同じボリュームを共有できます。Secret も同じ書き方で参照できます。`mount "cfg", from: settings, at: "/etc/app"` ではボリューム名を指定できます。PersistentVolumeClaim の宣言も同じように渡せます。`mount uploads, at: "/data"` で書き込み、読み取り専用のコンテナには `read_only: true` を付けます。ブロックモードの PVC には `device disk, at: "/dev/data"` を使います。

複数の設定を同じディレクトリに置くには `mount "cfg", from: [defaults, overrides], at: "/etc/app"` と書きます。同名のファイルには配列の後ろの内容が反映されます。

StatefulSet では `data = volume_claim_template "data" do ... end` でレプリカごとの PVC を宣言できます。ブロックに `access_modes ["ReadWriteOnce"]` や `resources { requests storage: "10Gi" }` を書き、初期化コンテナやアプリで `mount data, at: "/data"` と宣言を参照できます。`volume_mode "Block"` を指定した場合は `device data, at: "/dev/data"` を使います。

`empty_dir` の戻り値を Ruby の変数に入れると、初期化コンテナとアプリで同じボリュームを共有できます。既定はディスクで、`medium: :memory` で tmpfs を選べます。`size_limit:` はボリューム単位の上限です。

```ruby
pod "report" do
  restart_policy "Never"
  cache = empty_dir "cache", medium: :memory, size_limit: "32Mi"
  init_container("prepare", image: "busybox:1.36") do
    mount cache, at: "/out"
    command ["sh", "-c", "echo ready > /out/status"]
  end
  container("reader", image: "busybox:1.36") do
    mount cache, at: "/input", read_only: true
    command ["cat", "/input/status"]
  end
end
```

`in_namespace "preview" do ... end` で環境ごとの宣言をまとめられます。ブロック内の名前空間スコープのリソースには `preview` が補われ、各宣言の `namespace:` で上書きできます。ネストしたブロックを抜けると、外側の名前空間に戻ります。Namespace や ClusterRole など、クラスタスコープのリソースに名前空間は補われません。

```ruby
in_namespace "preview" do
  account = service_account "web"
  registry = secret "registry" do
    type "kubernetes.io/dockerconfigjson"
    string_data ".dockerconfigjson" => ENV.fetch("DOCKER_CONFIG_JSON")
  end

  deployment "web" do
    use_service_account account
    image_pull_secrets registry
    container "app", image: "registry.example.test/web:1"
  end
end
```

このファイルを rubectl で評価するときは `--env DOCKER_CONFIG_JSON` を付けます。ヘルパーは Pod、Deployment、Job、CronJob などの PodSpec に `serviceAccountName` と `imagePullSecrets` を設定します。宣言した参照先はワークロードと同じ名前空間に置きます。PodSpec に `image_pull_secrets [{name: "existing"}]` で一覧を指定している場合、Secret 名の重複を除いて追記します。クラスタにすでにある Secret は `image_pull_secrets secret("existing")` で参照できます。

`expose web, ports: {http: 80}` は、Deployment の名前空間とセレクタを引き継ぎ、コンテナの名前付きポート `http` を公開する Service を生成します。`prefer: :same_zone` または `prefer: :same_node` を加えると、Service の `trafficDistribution` で同じゾーンまたはノードのエンドポイントを優先します。ポート名や優先設定を書き間違えると、`render` と `apply` はクラスタへの送信前に Ruby の行番号と指定できる名前を表示します。

`ingress_for` は、`service` や `expose` で宣言した Service と同じ名前・名前空間に `networking.k8s.io/v1` の Ingress を生成します。Service のポートが TCP の1つだけなら `port:` を省略できます。複数ある場合は、`:http` や `80` のように TCP の Service ポートを名前または番号で指定します。既定は `path: "/"` と `path_type: :prefix` です。完全一致には `path_type: :exact`、IngressClass の選択には `class_name:` を使います。通信の処理はクラスタの Ingress コントローラーが行います。

`sidecar("proxy", image: "proxy:1") { port 8443, name: "https" }` は Kubernetes の再起動可能なサイドカーを宣言します。後続の初期化コンテナより先にプロキシが起動し、`expose web, ports: {https: 443}` からそのポートを参照できます。

ワークロードのブロックに `spread_across "topology.kubernetes.io/zone"` と書くと、ゾーン間の Pod 数の差を最大 1 に抑えます。後から書いた `matchExpressions` も含め、ワークロードのセレクターをそのまま使います。均等配置が難しいときも起動を優先するなら `when_unsatisfiable: :schedule_anyway` を指定します。

`autoscale web, replicas: 2..8, cpu: 70` と書くと、同じ名前空間に HorizontalPodAutoscaler を生成します。CPU 使用率がリクエストの 70% になるように、2〜8 レプリカの範囲で調整します。HPA に台数を任せるときは Deployment の `replicas` を省き、コンテナに CPU リクエストを設定します。稼働中の調整にはリソースメトリクス API が必要です。

プロキシのサイドカーを持つ Deployment で、アプリの負荷を基準に台数を変えたいときは、`autoscale web, replicas: 2..8, cpu: 70, container: :api` と書けます。CPU やメモリの使用率を指定コンテナだけで計算します。

RBS 対応エディタに gem の `sig/` を読み込むと、宣言やヘルパーのメソッド名を補完し、キーワード引数と型を参照できます。`:api` のようにマニフェスト内で宣言した名前は評価時に解決されます。コンテナ名を書き間違えると Ruby の行番号と指定できる名前を表示します。

Ruby マニフェストのトップレベルと `in_namespace` のブロックでは、`self` は `Rubernetes::Manifest::Builder` です。`resource` のブロックでは `Rubernetes::Manifest::ObjectBuilder` になります。Steep では Ruby のブロック内でレシーバーの型を指定します。この例の `tap` では、マニフェストのレシーバーをそのまま使えます。

```ruby
tap do
  # @type self: Rubernetes::Manifest::Builder
  web = deployment :web, namespace: :preview do
    container :api, image: "nginx:1.27" do
      port 80, name: "http"
      cpu request: "100m"
    end
  end

  frontend = expose web, ports: {http: 80}
  ingress_for frontend, host: "web.example.test", port: :http
  autoscale web, replicas: 2..8, cpu: 70, container: :api
  disruption_budget web, max_unavailable: "25%"
end
```

インストール済みの gem は `rbs -r rubernetes method Rubernetes::Manifest::Builder autoscale`、リポジトリでは `bundle exec rbs -I sig method Rubernetes::Manifest::Builder autoscale` でシグネチャを確認できます。

`rubectl plan -f web.rb --allow-code` は現在のクラスタで各宣言を server-side apply の dry-run にかけ、作成・更新・変更なしを表示します。たとえば `rollout_on` の対象データを編集すると、ConfigMap のキーと Deployment の Pod テンプレートが更新対象に出ます。出力には変更されるフィールドのパスだけが並ぶので、Secret の値を表示せずに確認できます。 `-o text` を付けると、`web.rb:8  UPDATE Deployment/prod/web` のように宣言のファイルと行を示し、その下に変更フィールドを並べます。

`plan` や `apply` で API が Ruby マニフェストのリソースを拒否すると、rubectl は種類・名前と宣言元の相対パス・行番号を表示し、Secret の値を伏せた API エラーを続けて出力します。

別の field manager が所有する ConfigMap のキーを変更すると、競合の詳細に所有者とフィールド名が出ます。`rubectl plan -f app.rb --allow-code -o text --field-manager ruby-two --force` で所有権を引き継いだ場合の差分を確認できます。変更は同じ field manager と `--force` を指定して `apply` した時点で反映されます。

```sh
ruby -Ilib exe/rubectl render -f web.rb --allow-code -o yaml | kubectl apply -f -
```

`selector`と、それに対応するテンプレートのラベルは、書かなくても補われます。フィールドはスキーマと照合されるので、書き間違いは適用の前に分かります。

```text
web.rb:9: containers.nginx.readinessProbe.httpGet: HTTPGetAction has no field "pathh" (did you mean "path"?)
```

繰り返し、条件分岐、共通部分のメソッド化には、Rubyをそのまま使います。ファイルは、ネットワークとクラスタの資格情報を持たない別プロセスで評価されます。例は[examples/manifests/](examples/manifests/README.ja.md)に、仕様は[spec/ruby/manifest-dsl.md](spec/ruby/manifest-dsl.md)にあります。

### CronJob の起動予定を確認する

CronJob を適用する前に起動予定を確認できます。次の宣言を `nightly.rb` に保存します。

```ruby
cron_job "nightly", namespace: "default" do
  schedule "30 1 * * *"
  time_zone "America/New_York"
  container("report", image: "busybox:1.36") { command ["echo", "ready"] }
end
```

```sh
rubectl cron -f nightly.rb --allow-code --from 2026-11-01T04:45:00Z --count 2
rubectl apply -f nightly.rb --allow-code
```

`cron` はクラスタに接続せず、指定した RFC3339 時刻より後の予定を CronJob ごとに既定で5件表示します。この例は夏時間の終了により、同じ日の `01:30:00-04:00` と `01:30:00-05:00` を表示します。表示には宣言した `time_zone` を使い、省略時は UTC です。`@every` は `--from` を起点に計算します。Job の作成時には、コントローラーが一時停止、同時実行ポリシー、開始期限も確認します。

## リポジトリ構成

| パス | 内容 |
|---|---|
| [`lib/rubernetes/`](lib/rubernetes/README.md) | 本体のコード。`api/`、`consensus/`、`scheduler/`、`node/`のようにサブシステムごとに分かれています |
| [`exe/`](exe/README.ja.md) | 6つの実行ファイル。オプションを解釈して`lib/rubernetes/bootstrap`に渡します |
| [`ext/rubernetes_linux/`](ext/README.md) | Cの拡張。`clone3`とexec、型付きのシステムコールを提供します |
| `schema/` | Kubernetes v1.36.2から取り込んだスキーマ、OpenAPI、既定値 |
| `generated/` | `schema/`から生成したRubyの型、RBS、コーデック、Manifest DSL。手では編集しません |
| [`spec/`](spec/README.md) | 仕様と設計書 |
| [`test/`](test/README.md) | unit、property、integration、e2e、chaos、security、compatibilityの各テストとconformanceのプロファイル |
| [`tools/`](tools/README.md) | Rubyで書いた自動化ツール。スキーマの取り込みと生成、conformance、マイルストーンのゲート、形式検証、リリース |
| [`verification/`](verification/README.md) | TLA+とLeanのモデル、トレースのスキーマ |
| [`third_party/locks/`](third_party/locks/README.md) | upstreamのソース、イメージ、バイナリをコミットとダイジェストで固定した一覧 |
| [`deploy/`](deploy/cluster/README.md) | systemdユニットと運用手順 |
| [`apps/dashboard/`](apps/dashboard/README.ja.md) | Rails製のダッシュボード兼メトリクスサーバ |
| `benchmarks/` | ベンチマーク |
| `artifacts/` | 証拠バンドル。Gitでは管理しません |

## 開発

```sh
bundle install
rake abi:compile                 # 最初に1回。以後はext/を変更したとき
rake test:parallel               # 全テストをファイルごとに別プロセスで実行。約6分。JOBS=nで並列数を指定
rake test                        # 直列実行。約1時間。証拠ゲートはこちらを使う
ruby -Ilib -Itest test/unit/some_test.rb -n /pattern/
rake lint                        # RuboCop。160桁、ダブルクォート
rake lint:fix                    # 安全な自動修正だけを適用。実行後はテストを回す
rake rbs:generate                # スキーマ更新後に Manifest のリソース宣言の型を再生成
rake rbs:validate                # 実際の DSL と型宣言の一致を確認し、RBS を検証
```

コードを変更するときは次の決まりを守ってください。

### 型はスキーマから生成する

Kubernetesの型を手で書かないでください。型を変えたいときは`tools/schema/`のimporterかgeneratorを直し、再生成します。生成物はバイト単位で再現できる必要があります。

### 振る舞いはupstreamと比べて確かめる

API、コントローラ、スケジューラ、kubeletの振る舞いを足したら、固定したKubernetesのバイナリかイメージと結果を比べるテストを付けてください。比べられない場合は、対応するupstreamのテストをもとにテストを書きます。自分がソースを読んで理解した内容だけを根拠にしないでください。

### 実行できなかった検査を合格にしない

アダプタ、カーネル機能、外部ランナーが足りないとき、検査は`INCOMPLETE`かエラーを報告します。免除する場合は名前と理由を記録してください。カーネルの免除の例が[tools/milestones/README.ja.md](tools/milestones/README.ja.md)にあります。

### ダックタイピングを前提にする

無効にしているRuboCopのcopは、理由とともに`.rubocop.yml`に並べてあります。その多くは、自動修正がレシーバの型を決め打ちするcopです。Structへの`grep`、Hashへの`partition`、`File::Stat`への`empty?`がその例にあたります。`rake lint`は違反ゼロを保ち、todoファイルは置きません。整形だけのコミットは`.git-blame-ignore-revs`に登録してください。

### requireを足したらlib全体を読み込む

`lib/`に`require`を足したら、次のコマンドでlib全体を一度読み込んでください。

```sh
ruby -Ilib -e 'require "rubernetes"'
```

`require_relative`の誤りは、そのファイルを読み込むプロセスを起動するまでエラーになりません。

### コミットはツールで作る

`rake repo:commit`を実行すると、ツールが作業ツリーの変更をコミットに分けます。`ruby tools/repo/auto_commit.rb --cycle <name> --status 0`でも同じです。ツールの動きは次のとおりです。

- 連続した編集1つを1コミットにします。
- 変更が属する宣言の名前をコミット名にします。
- ソース、テスト、ドキュメントの順に並べます。
- HEADへのcompare-and-swapで公開します。
- ステージしていない変更もコミットします。含めたくない変更は先にstashしてください。
- 著者以外のトレーラは付けません。

## 検証

検証は4種類あります。

### テスト

`rake test`で実行します。unit、property、integration、chaos、securityを合わせて約3,400ケースあります。コーデック、validation、server-side apply、コントローラ、スケジューラについては、Goで書いた基準実装と結果を比べるテストも含みます。

### Kubernetes Conformanceと互換性の検査

[tools/conformance](tools/conformance/README.ja.md)で実行します。検査はK0からK7までの8段階です。

| 段階 | 内容 |
|---|---|
| K0 | 入力の整合性 |
| K1 | 公式Conformanceスイート。Hydrophoneで実行 |
| K2 | Sonobuoyのcertified-conformance |
| K3 | e2eテスト全体。7,579件のspecを分類した台帳に従って実行 |
| K4 | node conformance |
| K5 | 本物のkube-apiserverとの結果比較 |
| K6 | upstreamのHelm chartとoperator 32件 |
| K7 | クラスタのライフサイクル |

K3の台帳は`test/compatibility/api/selection-ledger.json`です。プロファイルはIPv4、IPv6、dual-stackの3つで、どれもcontrol 3ノードとworker 3ノードの構成です。定義は`test/conformance/kubernetes/profiles.yml`にあります。

### 形式モデル

[verification/](verification/README.md)に置いてあります。Raftとランタイムのライフサイクルを、TLA+とLeanで記述しました。TLA+の検査にはTLCとApalacheを使います。本体が出力したジャーナルをトレースとして再生し、モデルと実装が一致するかを確かめます。実際のクライアント履歴を対象にした線形化可能性のチェッカもあります。

### マイルストーンの証拠ゲート

[tools/milestones](tools/milestones/README.ja.md)で実行します。マイルストーンはM0の実行基盤からM9のリリースまでの10段です。各段は検査結果を証拠バンドルにまとめ、ゲートがそのバンドルを再検査します。バンドルは前の段の結果を含むので、ソースを変えると後ろの段もすべて無効になります。コマンドは`rake m<n>:evidence`と`rake m<n>:verify`です。

## 現状と既知の制約

2026-10-01時点の状況です。

### プラットフォーム

Linux x86_64だけに対応しています。arm64は検証していません。カーネルは6.8以降で動かしています。M4の検査のうちSCTP CRC32cヘルパの1項目はカーネル6.12を必要とするので、古いカーネルでは免除として記録しています。

### ネットワーク

Podネットワークの既定は内蔵のbridgeです。エージェントの設定で`network.plugin: cni`を指定するとCNIプラグインを実行できます。Conformanceでは内蔵のbridgeを使っています。

IPv6専用クラスタでは、`rubectl cluster up --ip-family ipv6 --nat64-prefix CIDR`で既存のNAT64ゲートウェイを利用できます。クラスタを起動する前に、そのプレフィックス宛てのIPv6通信がゲートウェイに届くようにノードの経路を設定します。詳細は[IPv6専用Podからの送信](spec/node/network.md#sec-5-9-9)を参照してください。

Ruby では `expose web, ports: {http: 80}, type: :load_balancer, load_balancer_class: "rubernetes.io/routed", allocate_node_ports: false` と書くと、NodePort を消費せずに Service を公開できます。ベアメタルでは、`rubectl cluster up --load-balancer-pool CIDR` と `rubernetes.io/routed` クラスで、ルーティング済みのIPプールからLoadBalancer Serviceを公開できます。クラウド環境ではプロバイダが提供する外部Cloud Controller Managerを利用できます。設定手順は[LoadBalancer Services](deploy/cluster/README.md#loadbalancer-services)を参照してください。

外部Cloud Controller Managerを使わないローカルクラスタでは、`rubectl cluster up --load-balancer-pool CIDR --default-routed-load-balancer` で、`spec.loadBalancerClass` を省略するチャートにもアドレスを割り当てられます。すでにプールを設定済みのクラスタでは、停止中に `config/controller-manager.yml` のコントローラ設定に `default_routed_load_balancer: true` を追加し、`rubectl cluster start` で再起動できます。

### 規模

計測はすべて、1台のホスト上に作った6ノードのクラスタで行いました。複数ホストの構成も同じYAMLで組めますが、通しでの検証はしていません。

### メトリクス

各コンポーネントの `/metrics` は、cAdvisor や kube-proxy を含む upstream のメトリクス名を公開します。etcd のリースや Windows HostProcess コンテナなど、該当する計測対象がない系列では、サンプルを出さない理由を HELP に記載します。コンポーネントごとの一覧は [metrics.rb](lib/rubernetes/observability/metrics.rb) にあります。

### Alpha API

Alpha の API バージョンは `--runtime-config` で有効にし、必要に応じて対応する feature gate も有効にします。Kubernetes v1.36.2 のコーパスで Alpha に分類される44件について、対象の挙動、実装やテストへのリンク、特定のカーネル・ランタイム・デバイスでの確認が残る項目をまとめています。[Alpha feature gate の対応表](spec/verification/alpha-feature-gates.md)

### 証拠バンドル

ディスク上のバンドルは、最新のソース変更より前に作ったものです。そのため現在のソースに対しては無効です。ゲートとConformanceは現在のツリーで再実行しました。リリース候補を作るときはM0からM9まで取り直す必要があります。

### Lint

`rake lint`はツリー全体で違反ゼロです。

## ドキュメント

- [仕様の目次](spec/README.md)と[アーキテクチャ](spec/foundation/architecture.md)
- [Rubyで書く拡張の仕様](spec/ruby/extensions.md)と[例](examples/extensions/README.ja.md)
- [マイルストーンと完了ゲート](spec/delivery/milestones.md)
- [Kubernetes互換性の試験](spec/verification/kubernetes-compatibility.md)
- [コーディング規約](spec/delivery/coding-standards.md)と[プロジェクト構成](spec/delivery/project-structure.md)
- [クラスタの運用](deploy/cluster/README.md)
- [Conformanceツール](tools/conformance/README.ja.md)と[マイルストーンゲート](tools/milestones/README.ja.md)

## ライセンス

Apache License 2.0です。全文は[LICENSE](LICENSE)にあります。upstream由来の部分とそのライセンスは[NOTICE](NOTICE)に記載しています。
