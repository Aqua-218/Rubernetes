# Rubernetes

[English](README.md) | 日本語

Rubernetes は、Kubernetes v1.36.2 を Linux 向けに Ruby 中心で独立実装した
ものです。API サーバ、Raft データストア、コントローラ、スケジューラ、独自の
コンテナランタイムを持つノードエージェント、Pod ネットワーク、サービス
プロキシ、クラスタ DNS、ボリューム経路のすべてがプロジェクト自身の Ruby
コードです。Kubernetes のコードは固定したテストオラクルとしてのみ使い、
依存にはしません。クラスタは Kubernetes API をそのまま話すので、`kubectl`、
Helm、client-go、upstream の chart は無改変で動きます。

| | |
|---|---|
| Kubernetes 互換契約 | v1.36.2（`status.nodeInfo.kubeletVersion` にもこの値を報告） |
| 直近のフル Conformance | 459 / 459 合格、2026-09-30、`linux-amd64-ipv4-native`、無改変の `registry.k8s.io/conformance` イメージを Hydrophone で実行 |
| 対象環境 | Linux x86_64、cgroup v2、root。Ruby 3.4.11 |
| 規模 | `lib/` と `ext/` の Ruby と C が約 22 万行、テストが約 10 万行 |
| ライセンス | Apache-2.0 |

規範仕様は [`spec/`](spec/README.md) にあります。この README は実用面の
入口です。

## 中身

| Rubernetes のプロセス | 相当する upstream | 内容 |
|---|---|---|
| `rubernetes-apiserver` | kube-apiserver + etcd | v1.36.2 のデフォルト API 面と discovery を完全に提供。JSON/YAML/Protobuf、watch、patch、field manager 付き server-side apply、admission（固定コーパス由来のプラグイン、webhook、CEL ポリシー）、認証・認可、API Priority and Fairness、監査、保存時暗号化、CRD、API aggregation、feature gate と `--runtime-config`。ストレージは内蔵の Raft データストア（`lib/rubernetes/consensus/`）: CRC-32C WAL、スナップショット、joint consensus、pre-vote、ReadIndex、相互 TLS。 |
| `rubernetes-controller-manager` | kube-controller-manager | upstream のコントローラ群（ワークロード、GC、namespace、Endpoints と EndpointSlice、ServiceAccount とトークン、node lifecycle、CSR 承認、PV/PVC、quota など）を informer / work queue フレームワークとリーダー選出の上で実行。 |
| `rubernetes-scheduler` | kube-scheduler | デフォルトプラグイン一式を持つスケジューリングフレームワーク、preemption、非同期 bind、scoring。 |
| `rubernetes-agent` | kubelet + CRI ランタイム + CNI | Pod sync loop、probe、eviction、graceful node shutdown、device plugin、CPU/memory/topology manager、DRA、kubelet API（`exec`、`logs`、`/metrics*`、`/configz` など）。ランタイムは **native**（clone3、cgroup v2、namespace、OCI イメージの取得と検証も Ruby）、**microvm**（jailer 付き Firecracker、dm-verity rootfs、vsock supervisor）、オプトインの **CRI** バックエンド。ネットワークは内蔵 bridge データパスで、dual-stack IPAM、NetworkPolicy（nftables または eBPF）、egress NAT、プロセス内クラスタ DNS を持つ。 |
| `rubernetes-proxy` | kube-proxy | Service、EndpointSlice、NodePort、session affinity、traffic policy。**iptables**、**nftables**、**eBPF** の 3 データパスを upstream と同じチェーン構成とメトリクスで実装。 |
| `rubectl` | kubectl（部分集合） | `get`、`create`、`apply`、`patch`、`delete`、`watch`、`raw`。スキーマコーパスから生成した Ruby Manifest DSL も読める。本物の `kubectl` もそのまま使える。 |
| `apps/dashboard` | Kubernetes dashboard + Prometheus | Rails アプリ。クラスタブラウザ、Prometheus 型の自前時系列ストア、PromQL、recording / alerting ルール、Prometheus 互換 HTTP API。[個別 README](apps/dashboard/README.ja.md) 参照。 |

実行時に必要なのは Ruby と、fork する Ruby VM から安全に発行できない
システムコールのための小さな C シム（[`ext/rubernetes_linux`](ext/README.ja.md)）
だけです。

## クイックスタート

必要なもの: cgroup v2 の Linux x86_64、root、`nft` と `iptables`、Ruby 3.4.11
（Gemfile が固定）、イメージ取得のための外向き通信、`build/tools/kubectl-v1.36.2`
に置いた kubectl v1.36.2（チェックサムは `test/compatibility/clients/matrix.yml`）。
KVM は `microvm` RuntimeClass を使うときだけ要ります。

```sh
git clone <this repository> && cd 2026
bundle install
rake abi:compile                    # C シムを build/ 配下にビルド

# このホスト上に control 3 ノード + worker 3 ノードのクラスタを、PKI・
# コンポーネントごとの identity・クラスタ DNS・kubeconfig 込みで /srv/rbn-dev に作る:
sudo -E ruby tools/conformance/cluster.rb up --profile linux-amd64-ipv4-native --root /srv/rbn-dev

export KUBECONFIG=/srv/rbn-dev/linux-amd64-ipv4-native/kubeconfig
kubectl get nodes
kubectl create deployment web --image=nginx --replicas=3
kubectl expose deployment web --port=80 --type=NodePort
kubectl get pods -o wide

sudo ruby tools/conformance/cluster.rb status --root /srv/rbn-dev
sudo ruby tools/conformance/cluster.rb down   --root /srv/rbn-dev
```

`cluster.rb` は conformance 実行にも使っているもので、正しい構成の参照実装
です（`<root>/<profile>/cluster.json` にすべてのプロセス・ポート・ファイルが
並びます）。共用ホストで動かす前に 2 点: `up` は
`<RUBERNETES_M8_CGROUP_ROOT>/rubernetes`（既定 `/sys/fs/cgroup/rubernetes`）
配下のワークロードを殺し、自分のネットワーク名前空間内の古い `rbn*` ブリッジと
`rbn-*` 名前空間を消します。また同じネットワーク名前空間で別 root のクラスタが
生きていれば起動を拒否します。1 ホストで複数クラスタを動かすには
`tools/conformance/netns_env.sh` でクラスタごとにネットワーク名前空間を
与えてください。手順は [tools/conformance/README.ja.md](tools/conformance/README.ja.md)
にあります。

リリース成果物からの常設インストール（systemd ユニット、PKI、アップグレード、
バックアップとリストア）は [deploy/cluster/README.md](deploy/cluster/README.md)
を読んでください。各デーモンは YAML 1 ファイル（`--config`、`--check-config`
で検証）だけを読み、環境変数は読みません。`config/defaults/` に版付きの
既定値があります。

### ダッシュボードとメトリクス

```sh
cd apps/dashboard && bundle install
RUBERNETES_KUBECONFIG=$KUBECONFIG bin/rails server -p 3000
```

`http://localhost:3000` を開きます。ダッシュボードは全 API サーバ、全
kubelet エンドポイント、アノテーション付き Pod/Service を自前ストアに
scrape するので、Grafana の Prometheus データソース（`/api/v1/query` など）
としても使えます。

## リポジトリ構成

| パス | 内容 |
|---|---|
| [`lib/rubernetes/`](lib/rubernetes/README.md) | 本番コード。サブシステムごとに 1 ディレクトリ（`api/`、`consensus/`、`controller/`、`scheduler/`、`node/`、`runtime/`、`network/`、`proxy/`、`volume/`、`security/`、`schema/`、`observability/` など） |
| [`exe/`](exe/README.ja.md) | 6 つの実行ファイル。オプションを解釈して `lib/rubernetes/bootstrap` に渡すだけ |
| [`ext/rubernetes_linux/`](ext/README.md) | C の ABI シム（`clone3` + exec、型付きシステムコール）。ポリシーは置かない |
| `schema/` → `generated/` | 取り込んだ Kubernetes v1.36.2 のスキーマ・OpenAPI・既定値コーパスと、そこから再現可能に生成した Ruby 型、RBS、コーデック、Manifest DSL。`generated/` は手で編集しない |
| [`spec/`](spec/README.md) | 規範仕様と設計書 |
| [`test/`](test/README.md) | unit、property、integration、e2e、chaos、security、compatibility の各スイートと conformance ハーネスのプロファイル |
| [`tools/`](tools/README.md) | Ruby 製の自動化: スキーマ取り込みと生成、conformance（`cluster.rb`、レーン、Hydrophone）、マイルストーンのプローブとゲート、形式検証ランナー、リリース成果物、コミット記録器 |
| [`verification/`](verification/README.md) | TLA+ と Lean のモデル（Raft、ランタイムライフサイクル、bounded framing、KV 逐次仕様）とトレースのスキーマ |
| [`third_party/locks/`](third_party/locks/README.md) | すべての upstream ソース、イメージ、ランナーバイナリ、ビルド入力をコミットとダイジェストで固定 |
| [`deploy/`](deploy/cluster/README.md) | systemd ユニットと運用手順 |
| [`apps/dashboard/`](apps/dashboard/README.ja.md) | Rails 製ダッシュボード / メトリクスサーバ |
| `benchmarks/`、`artifacts/` | ベンチマークと（Git 管理外の）証拠バンドル |

## 開発

```sh
bundle install
rake abi:compile                 # 最初に 1 回、以後 ext/ を触ったとき
rake test:parallel               # 全スイートをファイルごとに別プロセスで。JOBS=n で幅を指定（約 6 分）
rake test                        # 証拠ゲートが使う直列実行（約 1 時間）
ruby -Ilib -Itest test/unit/some_test.rb -n /pattern/
rake lint                        # RuboCop。Layout/Style は厳格、160 桁、ダブルクォート
rake lint:fix                    # safe な自動修正のみ。実行後は必ずテストを回す
rake rbs:validate                # 手書き RBS のベースライン
```

守るべき約束事:

- **型の正はスキーマコーパス。** Kubernetes の型を手書きしない。`tools/schema/`
  の importer / generator を変えて再生成する。生成物はバイト単位で再現可能で
  あること。
- **振る舞いは upstream と突き合わせて確かめる。自分の読解と突き合わせない。**
  新しい API・コントローラ・スケジューラ・kubelet の振る舞いには、可能なら
  固定した Kubernetes バイナリ／イメージに対する differential かオラクルの
  テストを、無理なら対応する upstream テストから起こしたテストを付ける。
- **黙ってスキップしない。** アダプタ、カーネル機能、外部ランナーが無ければ
  `INCOMPLETE` かエラーとして報告し、合格にはしない。免除（waiver）は名前と
  理由を記録する（[tools/milestones/README.ja.md](tools/milestones/README.ja.md)
  のカーネル waiver を参照）。
- **ダックタイピングは意図的。** 無効化している RuboCop の cop は全て理由付きで
  `.rubocop.yml` に列挙してある。大半は自動修正がレシーバの具象型を仮定するもの
  （Struct への `grep`、Hash への `partition`、`File::Stat` への `empty?`）。
  `rake lint` は常に違反ゼロで、todo ファイルは無い。整形のみのコミットは
  `.git-blame-ignore-revs` に列挙。
- **`lib/` に `require` を足したら lib 全体を 1 度ロードする**
  （`ruby -Ilib -e 'require "rubernetes"'`）。壊れた `require_relative` は
  それを必要とするプロセスでしか露見しない。
- **コミットは書くのではなく記録する。** `rake repo:commit`（または
  `ruby tools/repo/auto_commit.rb --cycle <name> --status 0`）が作業ツリーを
  「連続した編集 1 つ = 1 コミット」に変換し、変更が属する宣言名でコミット名を
  付け、ソース → テスト → ドキュメントの順で、HEAD への compare-and-swap で
  公開する。未ステージの変更もコミットするので、載せたくないものは stash
  しておく。著者以外のトレーラは付けない。

## 検証

4 層あり、それぞれ専用のツールがあります。

1. **テスト**（`rake test`）: unit、property、integration、chaos、security の
   約 3,400 ケースに加え、コーデック、validation、server-side apply、
   コントローラ、スケジューラの Go オラクル differential。
2. **Kubernetes Conformance と互換レーン**
   （[tools/conformance](tools/conformance/README.ja.md)）: K0 入力整合性、
   K1 公式 Conformance スイート（Hydrophone）、K2 Sonobuoy certified-conformance、
   K3 選択台帳に基づく e2e 全量（`test/compatibility/api/selection-ledger.json`、
   7,579 spec を分類済み）、K4 node conformance、K5 本物の kube-apiserver との
   differential、K6 固定した upstream の Helm chart と operator 32 件のコーパス、
   K7 クラスタライフサイクル。プロファイルは IPv4、IPv6、dual-stack の 3 つで、
   いずれも control 3 + worker 3（`test/conformance/kubernetes/profiles.yml`）。
3. **形式モデル**（[verification/](verification/README.md)）: Raft とランタイム
   ライフサイクルを TLA+（TLC、Apalache）と Lean で記述し、本番ジャーナルから
   再生したトレースで実装と結び付ける。実クライアント履歴に対する
   線形化可能性チェッカも含む。
4. **マイルストーン証拠ゲート**（[tools/milestones](tools/milestones/README.ja.md)）:
   M0（実行基盤）から M9（リリース）まで、各段が内容アドレスの証拠バンドルを
   作り、厳格なゲートが再検査する。連鎖は累積的で、ソースが変わると無効になる。
   `rake m<n>:evidence`、`rake m<n>:verify`。

## 現状と既知の制約

2026-10-01 時点の正直な一覧:

- **プラットフォーム。** Linux x86_64 のみ。arm64 は未検証。カーネルは 6.8 以降で
  動かしている。M4 の 1 項目（SCTP CRC32c ヘルパ）は 6.12 を要求し、古い
  カーネルでは明示的に waiver している。
- **ネットワーク。** Pod ネットワークは内蔵 bridge データパスで、外部 CNI
  プラグインは実行しない。IPv6 専用クラスタに NAT64 はない。クラウド
  プロバイダ連携はなく、LoadBalancer Service はベアメタル同様、外部が設定
  しない限り pending のまま。
- **規模。** 計測したものはすべて 1 ホスト上のマルチノードクラスタ（control 3、
  worker 3）。複数ホスト運用は同じ YAML で構成できるが、end to end では
  未検証。
- **メトリクス。** 各コンポーネントの `/metrics` は cadvisor や kube-proxy を含め
  upstream のファミリを揃えている。Go ランタイム内部や Rubernetes に相当物の
  無い機能を表す apiserver 27 件・kubelet 2 件は、「未実装」の HELP 文字列付きで
  登録され常に空（upstream 向けダッシュボードがそのまま読み込めるように）。
- **Alpha API** は upstream と同様、`--runtime-config` で有効にしたときだけ
  提供する。ほとんどの alpha feature gate の背後に実装はない。
- **証拠バンドル** はディスク上のものが最新のソース変更より前のもので、
  構造上 stale。ゲートと Conformance は現在のツリーで再実行済みだが、
  リリース候補では M0〜M9 の連鎖を取り直す必要がある。
- **Lint 負債。** `.rubocop_todo.yml` に過去の RuboCop 違反が約 3,000 件残る
  （大半は行長）。新規コードは違反ゼロが条件。

## ドキュメント

- [仕様インデックス](spec/README.md) と [アーキテクチャ](spec/foundation/architecture.md)
- [マイルストーンと完了ゲート](spec/delivery/milestones.md)
- [Kubernetes 互換性試験契約](spec/verification/kubernetes-compatibility.md)
- [Coding standards](spec/delivery/coding-standards.md) と [Project structure](spec/delivery/project-structure.md)
- [クラスタの運用](deploy/cluster/README.md)
- [Conformance ツール](tools/conformance/README.ja.md) と [マイルストーンゲート](tools/milestones/README.ja.md)

## ライセンス

Apache License 2.0。[LICENSE](LICENSE) を参照。
