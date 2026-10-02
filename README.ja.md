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
| 公式Conformance | 459件中459件合格（2026-09-30、IPv4プロファイル） |
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

- native: clone3、cgroup v2、namespaceを直接使います。OCIイメージの取得と検証もRubyで行います。
- microvm: jailer付きのFirecrackerでPodを動かします。rootfsはdm-verityで検証し、vsock経由のsupervisorが中で動きます。
- CRI: 外部のCRIランタイムにつなぎます。明示的に有効にしたときだけ使われます。

Podネットワークは内蔵のbridgeデータパスです。dual-stackのIPAM、NetworkPolicy、egress NAT、クラスタDNSを持っています。NetworkPolicyはnftablesかeBPFで実現します。

### rubernetes-proxy

Service、EndpointSlice、NodePort、session affinity、traffic policyを処理します。データパスはiptables、nftables、eBPFの3種類です。チェーンの構成とメトリクスはupstreamに合わせました。

### rubectl

`get`、`create`、`apply`、`patch`、`delete`、`watch`、`raw`が使えます。スキーマから生成したRubyのManifest DSLも読み込めます。本物の`kubectl`を使ってもかまいません。

### apps/dashboard

Railsで書いたダッシュボードです。クラスタの中身を閲覧でき、Prometheus形式の時系列ストアを自前で持っています。PromQL、recordingルール、alertingルール、Prometheus互換のHTTP APIに対応しています。詳しくは[ダッシュボードのREADME](apps/dashboard/README.ja.md)を読んでください。

## クイックスタート

次のものを用意してください。

- cgroup v2が有効なLinux x86_64とroot権限
- `nft`と`iptables`
- Ruby 3.4.11（Gemfileで固定しています）
- イメージを取得するための外向き通信
- `build/tools/kubectl-v1.36.2`に置いたkubectl v1.36.2

kubectlのチェックサムは`test/compatibility/clients/matrix.yml`に書いてあります。KVMは`microvm` RuntimeClassを使うときだけ必要です。

```sh
git clone <this repository> && cd 2026
bundle install
rake abi:compile                    # Cの拡張をbuild/配下にビルド

# control 3ノードとworker 3ノードのクラスタを/srv/rbn-devに作る
sudo -E ruby tools/conformance/cluster.rb up --profile linux-amd64-ipv4-native --root /srv/rbn-dev

export KUBECONFIG=/srv/rbn-dev/linux-amd64-ipv4-native/kubeconfig
kubectl get nodes
kubectl create deployment web --image=nginx --replicas=3
kubectl expose deployment web --port=80 --type=NodePort
kubectl get pods -o wide

sudo ruby tools/conformance/cluster.rb status --root /srv/rbn-dev
sudo ruby tools/conformance/cluster.rb down   --root /srv/rbn-dev
```

`cluster.rb up`は1台のホスト上に6ノードのクラスタを作ります。PKI、コンポーネントごとのidentity、クラスタDNS、kubeconfigも同時に用意します。起動したプロセス、ポート、ファイルの一覧は`<root>/<profile>/cluster.json`で確認できます。Conformanceの実行にも同じスクリプトを使っているので、正しい構成の見本として読めます。

### 共用ホストで動かすときの注意

`up`は起動前に次のものを消します。

- `/sys/fs/cgroup/rubernetes`配下で動いているワークロード。場所は`RUBERNETES_M8_CGROUP_ROOT`で変えられます。
- 同じネットワーク名前空間にある古い`rbn*`ブリッジと`rbn-*`名前空間

同じネットワーク名前空間で別のrootのクラスタが動いている場合、`up`は起動を拒否します。1台で複数のクラスタを動かすときは、`tools/conformance/netns_env.sh`でクラスタごとにネットワーク名前空間を分けてください。手順は[tools/conformance/README.ja.md](tools/conformance/README.ja.md)にあります。

### 常設インストール

リリース成果物から常設のクラスタを作る手順は[deploy/cluster/README.md](deploy/cluster/README.md)にあります。systemdユニット、PKI、アップグレード、バックアップとリストアを扱っています。

各デーモンは`--config`で渡したYAMLファイル1つだけを読み、環境変数は読みません。`--check-config`を付けると設定を検証できます。既定値は`config/defaults/`にバージョンごとに置いてあります。

### ダッシュボードとメトリクス

```sh
cd apps/dashboard && bundle install
RUBERNETES_KUBECONFIG=$KUBECONFIG bin/rails server -p 3000
```

起動したら`http://localhost:3000`を開いてください。ダッシュボードはすべてのAPIサーバとkubelet、それにアノテーションの付いたPodとServiceからメトリクスを集めて自前のストアに保存します。`/api/v1/query`などのPrometheus互換APIがあるので、GrafanaのPrometheusデータソースとしても使えます。

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
rake rbs:validate                # 手書きのRBSを検証
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

Podネットワークは内蔵のbridgeデータパスだけで、外部のCNIプラグインは実行しません。IPv6専用クラスタにNAT64はありません。クラウドプロバイダとの連携もありません。そのためLoadBalancer Serviceは、外部から設定しない限りpendingのままです。

### 規模

計測はすべて、1台のホスト上に作った6ノードのクラスタで行いました。複数ホストの構成も同じYAMLで組めますが、通しでの検証はしていません。

### メトリクス

各コンポーネントの`/metrics`は、cadvisorとkube-proxyの分を含めてupstreamと同じメトリクス名を出力します。ただしapiserverの27件とkubeletの2件は値を出しません。Goランタイムの内部や、Rubernetesに対応する機能がないものを表すメトリクスだからです。この29件はHELPに「未実装」と書いて登録だけしてあり、upstream向けのダッシュボードをそのまま読み込めます。

### Alpha API

upstreamと同じく、`--runtime-config`で有効にしたときだけ提供します。alphaのfeature gateの多くには実装がありません。

### 証拠バンドル

ディスク上のバンドルは、最新のソース変更より前に作ったものです。そのため現在のソースに対しては無効です。ゲートとConformanceは現在のツリーで再実行しました。リリース候補を作るときはM0からM9まで取り直す必要があります。

### Lint

`rake lint`はツリー全体で違反ゼロです。

## ドキュメント

- [仕様の目次](spec/README.md)と[アーキテクチャ](spec/foundation/architecture.md)
- [マイルストーンと完了ゲート](spec/delivery/milestones.md)
- [Kubernetes 互換性試験契約](spec/verification/kubernetes-compatibility.md)
- [Coding standards](spec/delivery/coding-standards.md) と [Project structure](spec/delivery/project-structure.md)
- [クラスタの運用](deploy/cluster/README.md)
- [Conformance ツール](tools/conformance/README.ja.md) と [マイルストーンゲート](tools/milestones/README.ja.md)

## ライセンス

Apache License 2.0。[LICENSE](LICENSE) を参照。
