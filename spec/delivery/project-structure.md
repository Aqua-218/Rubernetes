[仕様書の目次](../README.md) / [実装と納品](README.md)

<a id="project-structure"></a>
# プロジェクト構成

> 対象読者: 実装者、レビュア、ビルドの担当者、検証者
>
> **Status:** Normative — version 0.3

Ruby中心のproduction code、生成物、Linux ABI shim、upstream互換試験、形式仕様を
混同しないsource tree layoutと依存方向を定義する。directoryの存在は実装完了を意味せず、
完了状態は[マイルストーン](milestones.md)のevidenceだけで判定する。

## Source Tree

```text
.
├── README.md
├── Gemfile
├── Rakefile
├── rubernetes.gemspec
├── spec.md
├── spec/                         # Normative specification and design source of truth
│   ├── foundation/
│   ├── ruby/
│   ├── api/
│   ├── control-plane/
│   ├── node/
│   ├── verification/
│   ├── delivery/
│   └── diagrams/
├── exe/                          # Thin process entry points; no domain policy
│   ├── rubectl
│   ├── rubernetes-apiserver
│   ├── rubernetes-controller-manager
│   ├── rubernetes-scheduler
│   ├── rubernetes-agent
│   └── rubernetes-proxy
├── lib/
│   ├── rubernetes.rb             # Public namespace entry
│   └── rubernetes/
│       ├── version.rb
│       ├── bootstrap/             # Config, dependency graph, process lifecycle
│       ├── schema/                # Schema DSL/compiler/registry/codec/defaulting
│       ├── api/                   # HTTP, authn/z, admission, patch/apply, watch
│       ├── storage/               # Store interface and object persistence
│       ├── consensus/             # Raft, WAL, snapshot, membership
│       ├── watch/                 # Watch cache, Informer, index, WorkQueue
│       ├── controller/            # Controller DSL and built-in controllers
│       ├── scheduler/             # Scheduling framework and plugins
│       ├── node/                  # Node registration and Pod SyncLoop
│       ├── image/                 # OCI pull, verify, unpack and cache
│       ├── runtime/
│       │   ├── native/             # Namespace/cgroup/seccomp process backend
│       │   └── microvm/            # Firecracker/jailer/vsock backend
│       ├── network/               # Netlink, IPAM, VXLAN, policy and DNS
│       ├── proxy/                 # eBPF and nftables Service backends
│       ├── volume/                # Volume, PV/PVC, snapshot and CSI bridge
│       ├── security/              # Identity, policy, audit and secret primitives
│       ├── observability/         # Events, metrics, traces and evidence export
│       ├── platform/linux/        # Typed Ruby adapters over Linux ABI
│       └── support/               # Policy-free shared primitives
├── ext/rubernetes_linux/
│   ├── include/                   # Generated/hand-reviewed minimal C headers
│   └── src/                       # ABI shim only; no orchestration policy
├── schema/
│   ├── kubernetes/v1.36.2/       # Normalized pinned Kubernetes schema inputs
│   └── rubernetes/                # Project extension schema inputs
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
