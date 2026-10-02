[仕様書の目次](../README.md) / [実装と納品](README.md)

<a id="project-structure"></a>
# プロジェクト構成

> 対象読者: 実装者、レビュア、ビルドの担当者、検証者
>
> 状態: 規範、版0.3

ソースツリーの配置と、依存の方向を定義する。Ruby中心の本番コード、生成物、LinuxのABI用のshim、upstreamとの互換性試験、形式仕様が混ざらないようにする。

ディレクトリがあることは、実装が完了していることを意味しない。完了しているかどうかは、[マイルストーン](milestones.md)の証拠だけで判定する。

## ソースツリー

```text
.
├── README.md
├── LICENSE
├── NOTICE                        # upstream由来の部分の出典とライセンス
├── Gemfile
├── Rakefile
├── rubernetes.gemspec
├── spec.md
├── spec/                         # 仕様と設計書の正本
│   ├── foundation/
│   ├── ruby/
│   ├── api/
│   ├── control-plane/
│   ├── node/
│   ├── verification/
│   ├── delivery/
│   └── diagrams/
├── exe/                          # 薄いプロセスの入口。ドメインのポリシーは置かない
│   ├── rubectl
│   ├── rubernetes-apiserver
│   ├── rubernetes-controller-manager
│   ├── rubernetes-scheduler
│   ├── rubernetes-agent
│   └── rubernetes-proxy
├── lib/
│   ├── rubernetes.rb             # 公開する名前空間の入口
│   └── rubernetes/
│       ├── version.rb
│       ├── bootstrap/             # 設定、依存のグラフ、プロセスのライフサイクル
│       ├── schema/                # スキーマDSL、コンパイラ、レジストリ、コーデック、defaulting
│       ├── api/                   # HTTP、認証と認可、admission、patchとapply、watch
│       ├── storage/               # Storeのインターフェースとオブジェクトの永続化
│       ├── consensus/             # Raft、WAL、スナップショット、メンバーシップ
│       ├── watch/                 # watchキャッシュ、informer、インデックス、WorkQueue
│       ├── controller/            # Controller DSLと組み込みのコントローラ
│       ├── scheduler/             # スケジューリングフレームワークとプラグイン
│       ├── node/                  # ノードの登録とPodのSyncLoop
│       ├── image/                 # OCIイメージの取得、検証、展開、キャッシュ
│       ├── runtime/
│       │   ├── native/             # namespace、cgroup、seccompによるプロセスのbackend
│       │   └── microvm/            # Firecracker、jailer、vsockによるbackend
│       ├── network/               # netlink、IPAM、VXLAN、ポリシー、DNS
│       ├── proxy/                 # eBPFとnftablesによるServiceのbackend
│       ├── volume/                # ボリューム、PVとPVC、スナップショット、CSIとの接続
│       ├── security/              # identity、ポリシー、監査、secretの基本部品
│       ├── observability/         # イベント、メトリクス、トレース、証拠の出力
│       ├── platform/linux/        # LinuxのABIを型付きで扱うRubyのアダプタ
│       └── support/               # ポリシーを持たない共通の基本部品
├── ext/rubernetes_linux/
│   ├── include/                   # 生成した、または手でレビューした最小限のCヘッダ
│   └── src/                       # ABI用のshimだけ。オーケストレーションのポリシーは置かない
├── schema/
│   ├── kubernetes/v1.36.2/       # 正規化して固定したKubernetesのスキーマ入力
│   └── rubernetes/                # プロジェクト独自の拡張スキーマの入力
├── generated/
│   ├── ruby/                      # Generated types, codecs and validators
│   ├── rbs/                       # Generated public signatures
│   ├── openapi/                   # Generated served schemas
│   └── fixtures/                  # Generated round-trip/differential fixtures
├── sig/                           # Hand-authored RBS outside generated surface
├── config/
│   ├── defaults/                  # Versioned default process configuration
│   └── policies/                  # Admission, audit and runtime policy inputs
├── test/
│   ├── unit/
│   ├── property/
│   ├── integration/
│   ├── e2e/
│   ├── conformance/kubernetes/    # Unmodified upstream test runner profiles
│   ├── compatibility/
│   │   ├── api/                    # Request/response differential corpus
│   │   ├── clients/                # kubectl/client-go/Helm/Kustomize matrix
│   │   └── projects/               # Unmodified Chart and Operator corpus
│   ├── chaos/                      # Ruby scenario DSL and deterministic replay
│   ├── security/
│   ├── performance/
│   ├── support/
│   └── fixtures/
├── verification/
│   ├── tla/                       # TLA+ modules and TLC configurations
│   ├── lean/                      # Definitions, proofs and extracted oracles
│   └── traces/                    # Trace schema, refinement maps and regressions
├── tools/                         # Ruby-first repository automation
│   ├── schema/
│   ├── conformance/
│   ├── verification/
│   └── release/
├── third_party/
│   ├── locks/                     # Immutable source/artifact/image digests
│   └── cache/                     # Ignored downloaded upstream artifacts
├── examples/
│   ├── manifests/
│   ├── controllers/
│   └── scenarios/
├── benchmarks/
│   ├── api/
│   ├── runtime/
│   └── scheduler/
├── deploy/
│   ├── cluster/                   # Self-host/bootstrap deployment inputs
│   └── systemd/                   # Host service units and hardening overrides
├── packaging/                     # Reproducible package definitions
├── artifacts/                     # Ignored local/CI evidence output
├── build/                         # Ignored build output
└── tmp/                           # Ignored runtime scratch space
```

`exe/`の6ファイルはM0で生成または実装するrequired entryである。雛形段階では
`exe/README.md`がそのboundaryを保持し、実装されていないbinaryを成功するstubとして置いてはならない。

## Source Control Policy

project source treeにGit repositoryは作成しない。build、test、evidence、release automationは
Git command、commit SHA、branch、tag、working-tree状態へ依存してはならない。source identityと
cross-host evidence identityには、対象fileのrelative pathとSHA-256から生成する決定論的なinput digestを使う。

## Module Dependency Direction

```mermaid
graph TD
    Bootstrap["Bootstrap / exe"] --> API["API"]
    Bootstrap --> Control["Controllers / Scheduler"]
    Bootstrap --> Node["Node Agent"]
    API --> Schema["Schema / Generated Types"]
    API --> Storage["Store Contract"]
    API --> Security["Security"]
    Control --> Watch["Informer / WorkQueue"]
    Control --> API
    Control --> Schema
    Consensus["RaftStore"] --> Storage
    Node --> API
    Node --> Runtime["Runtime / Image"]
    Node --> DataPlane["Network / Proxy / Volume"]
    Runtime --> Platform["Linux Platform Adapter"]
    DataPlane --> Platform
    Schema --> Support["Policy-free Support"]
    Storage --> Support
    Platform --> Support
```

矢印は「左が右へ依存できる」を表す。逆向きimport、process singleton経由の隠れた逆依存、
constant lookupによる循環回避は禁止する。

## Layer Rules

### Public entry and bootstrap

- `lib/rubernetes.rb`は安定public namespaceだけをloadし、daemonを起動しない。
- `exe/*`はargument parse、config path確定、exit code変換だけを行う。
- `bootstrap/`だけがconcrete implementationを組み立てる。domain moduleはbootstrapへ依存しない。
- process間通信は[Architecture](../foundation/architecture.md)で定義したprotocol境界を越える。

### Schema and generated code

- `schema/`はcompiler input、`lib/rubernetes/schema/`はcompiler implementation、`generated/`はoutputである。
- generated Rubyは`Rubernetes::Generated`配下に置き、hand-authored classと同じconstantを再openしない。
- generated fileはgenerator version、input digest、output schema versionをheaderへ持つ。
- CIはgenerateを2回実行してbyte-identicalであることと、canonical generated treeとの差分0を検査する。

### Store and consensus

- `storage/`が`Store` interface、transaction、revision、watch eventの意味を所有する。
- `consensus/`は`Store`のdurable implementationを提供し、API object semanticsを所有しない。
- controller、scheduler、nodeはWALやRaft nodeへ直接アクセスせず、APIまたは明示したStore contractを使う。

### Node and Linux boundary

- `node/`はPod desired/observed stateとrollback順序を所有する。
- `runtime/`、`network/`、`proxy/`、`volume/`は互いのprivate implementationへ依存せず、Node Agentのcontractで接続する。
- `platform/linux/`はsyscall、netlink、BPF、KVM ABIをRuby objectとして公開するがpolicyを決めない。
- `ext/rubernetes_linux/`はFFIで安全に表現できないABI shimだけを含み、production sourceのRuby比率計算に含める。

### Verification and upstream code

- `test/conformance/kubernetes/`はpinned upstream binary/imageを実行するadapterだけを保持する。
- Kubernetes、etcd、runc/containerd、CNI/CSI oracle codeは`lib/`、`exe/`、production packageへ入れてはならない。
- upstream sourceとbinaryは`third_party/cache/`へ取得し、`third_party/locks/`のdigestと一致しなければ実行しない。
- TLA+/Lean sourceは`verification/`、Rubyとのrefinement/trace adapterは`lib/rubernetes/observability/`と
  `tools/verification/`に分ける。
- raw resultは`artifacts/`へ出力し、回帰入力へ採用した最小反例だけを`test/fixtures/`または
  `verification/traces/`へsource artifactとして保存する。

## Namespace Mapping

| Filesystem | Ruby namespace |
|---|---|
| `lib/rubernetes/api/` | `Rubernetes::API` |
| `lib/rubernetes/storage/` | `Rubernetes::Storage` |
| `lib/rubernetes/consensus/` | `Rubernetes::Consensus` |
| `lib/rubernetes/controller/` | `Rubernetes::Controller` |
| `lib/rubernetes/scheduler/` | `Rubernetes::Scheduler` |
| `lib/rubernetes/node/` | `Rubernetes::Node` |
| `lib/rubernetes/runtime/native/` | `Rubernetes::Runtime::Native` |
| `lib/rubernetes/runtime/microvm/` | `Rubernetes::Runtime::MicroVM` |
| `lib/rubernetes/platform/linux/` | `Rubernetes::Platform::Linux` |
| `generated/ruby/` | `Rubernetes::Generated` |

file path、module namespace、主要public class名は一致させる。acronymはRuby constantでは
`API`、`OCI`、`IPAM`、`UID`、`GVK`、`GVR`を用い、filenameでは`api`、`oci`、`ipam`、
`uid`、`gvk`、`gvr`を用いる。

## Test Placement Rule

testは対象classのdirectoryではなく、保証levelで配置する。同一behaviorにunit、property、integration、
E2Eがある場合は同じscenario IDをmetadataへ付ける。production bugから得た最小反例は、最も低いlevelで
再現するtestと、必要ならend-to-end regressionの両方へ固定する。

upstream testをcopyして改変したものはConformance evidenceに数えない。補助testとして保持する場合は
`test/compatibility/`へ置き、upstream file、commit、変更理由をmetadataへ記録する。

## Build and Artifact Policy

- source treeへのbuild output書込み先は`build/`だけとする。
- runtime scratchは`tmp/`、test/release evidenceは`artifacts/`へ分離する。
- `generated/`はsource artifactとして保持し、`build/`、`tmp/`、`artifacts/`はsource inputと配布物から除外する。
- release packageは`lib/`、`generated/ruby/`、必要な`config/`、native extensionだけを含める。
- `test/`、`verification/`、`third_party/cache/`、oracle binaryをproduction packageへ含めてはならない。

## Adding a Directory

新しいtop-level directoryは、既存boundaryで表現できず、次を同じ変更で満たす場合だけ追加する。

1. 本文にsingle responsibilityとownerを追加する。
2. dependency diagramへ依存方向を追加し、cycleが0であることを検査する。
3. build/package includeまたはexclude規則を更新する。
4. test placementとrelease artifactへの影響を定義する。
5. `spec/README.md`または該当family indexから到達可能にする。

## Related

- [マイルストーン](milestones.md)
- [Coding Standards](coding-standards.md)
- [Architecture](../foundation/architecture.md)
- [Kubernetes互換性試験](../verification/kubernetes-compatibility.md)
