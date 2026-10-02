[仕様書の目次](../README.md) / [基礎](README.md)

<a id="sec-1"></a>
# 1. 目的とスコープ

> 対象読者: 全読者、審査者、アーキテクト
>
> 状態: 規範、版0.2

Rubernetesの目的、Kubernetesとの互換性の境界、対象環境、規模、完成基準を定義する。

<a id="sec-1-1"></a>
## 1.1 目的

Kubernetes v1.36.2と外部から観測して互換なLinuxコンテナオーケストレータを、Rubyで実装する。既存のKubernetesマニフェスト、Helm chart、Operator、クライアントライブラリ、`kubectl`は、Rubernetes向けに変更しなくても動作する。

Kubernetesから利用するものは次のとおりである。

- APIスキーマ
- 公開プロトコル
- 規範となる挙動
- 適合試験と、差分テストの期待値

Kubernetesのバイナリとライブラリは、本システムの実行経路に組み込まない。APIサーバ、ストア、Raft、コントローラ、スケジューラ、ノードエージェント、コンテナランタイム、ネットワーク、サービスプロキシ、DNS、ボリューム管理は、Rubyを中心に独立して実装する。

挙動を一致させるために、upstreamのアルゴリズムをGoからRubyへ移植した箇所がある。移植した箇所は、移植元とライセンスをリポジトリ直下の`NOTICE`に記載しなければならない。

<a id="sec-1-2"></a>
## 1.2 達成基準

| # | 基準 | 検証方法 |
|---|---|---|
| G1 | 本物の`kubectl`が接続でき、`get`、`apply`、`delete`が通る | 実機でkubectlを実行する |
| G2 | 既存のDeploymentマニフェストが無改変で動作する | 公開されているnginxのDeploymentを適用する |
| G3 | Podがコンテナとして実際に隔離されて起動する | namespaceとcgroupを実機で確認する |
| G4 | ノード障害時にPodが別のノードで再作成される | 障害注入のシナリオを実行する |
| G5 | Raftの安全性が検証されている | 決定的な障害注入シミュレーションでTLA+の不変条件が成立する。`LogMatching`はLeanで全domainについて証明する |
| G6 | 主要なロジックがLeanで証明されている | `sorry`がゼロであることをCIで強制する |
| G7 | Kubernetes v1.36.2のLinux Conformanceと全API適合試験を通過する | upstreamの固定したテストコーパスを変更せずに実行する |
| G8 | 既存のHelm chartとOperatorが無変更で動く | 代表コーパスのinstall、upgrade、rollback、uninstall、reconcileを差分比較する |
| G9 | NativeとMicroVMの両ランタイムが、資源をリークせずfail-closedする | 実機での障害注入、再起動後の回復、TLA+トレースとの照合 |
| G10 | プロジェクト固有の本番コードの85%以上をRubyが占める | LOCをCIで集計する。生成物、vendor、fixture、TLA+、Lean、シェルは除く |
| G11 | 1つのスキーマ定義から、型とすべての派生成果物が一意に生成される | 再生成しても差分が出ないこと、生成物どうしが整合することをテストする |

G5では網羅的なモデル検査を行わない。[7.2](../verification/formal-methods.md#sec-7-2)の実測により、Raftでは完了しないことがわかっているためである。

<a id="sec-1-3"></a>
## 1.3 互換性の境界

互換性の規範対象は、Kubernetes v1.36.2がLinuxノード向けに公開する次の境界である。

- すべての組み込みAPIのgroup、version、resource、subresourceと、CRD
- defaulting、validation、conversion、admission。既定の状態と、feature gateを有効にした状態の両方を含む
- JSON、YAML、Kubernetes Protobuf、watch、exec、attach、port-forwardのワイヤプロトコル
- コントローラ、スケジューラ、ノード、ボリューム、ネットワーク、Service、DNSの、外部から観測できる挙動
- `kubectl`、client-go、Dynamic Client、Helm、Operatorから観測されるエラーの契約

「互換」とは内部構造が一致することではない。同じ前提状態と同じ要求に対して、次の項目が一致することをいう。

- 成功か失敗か
- HTTPステータス
- `Status.reason`、`Status.details`、`Status.causes`
- defaulting後のオブジェクト
- フィールドの所有権
- イベントの順序
- 最終的なクラスタの状態

UID、時刻、乱数、`resourceVersion`、ノード固有の値は、値そのものを比較しない。形式、単調性、一意性、因果の順序を比較する。

WindowsノードとWindowsコンテナは対象外とする。これは未実装の機能ではなく、プラットフォームの境界である。本システムはLinuxのシステムコール、KVM、cgroup v2を実行基盤にしている。

Linux上で実行できるKubernetes v1.36.2の機能は、後の段階や後続のスコープに先送りしない。

<a id="sec-1-4"></a>
## 1.4 前提環境

- Linux kernel 6.12以降。cgroup v2、OverlayFS、seccomp、Landlock、netlink、eBPF、KVMを使う
- x86_64またはaarch64
- Ruby 3.4以降
- cgroup v2 unified hierarchy、unprivileged user namespace、overlay、vxlan、br_netfilter、BPFが有効であること

Native backendは、特権を持つbootstrap helperを起動したあと、専用の非特権UIDに降格する。

MicroVM backendは、`/dev/kvm`、Firecracker 1.16.1、同じ版の`jailer`を使う。

<a id="sec-1-5"></a>
## 1.5 規模・可用性・性能

### 規模

Kubernetes v1.36がサポートする規模と同じ上限を扱う。

| 項目 | 上限 |
|---|---|
| 1クラスタあたりのノード数 | 5,000 |
| 1クラスタあたりのPod数 | 150,000 |
| 1クラスタあたりのコンテナ数 | 300,000 |
| 1ノードあたりのPod数 | 110 |

この範囲内で、APIスキーマ、カウンタ、キュー、リビジョン、識別子がオーバーフローしてはならない。意図しないハードリミットに達してもならない。

### 可用性

制御ノードは3台または5台で構成できる。`floor((N-1)/2)`台が停止していても、コミット済みの状態を失わない。

quorumが回復してから60秒以内に、APIへの書き込み、コントローラのreconcile、スケジューラのbindを再開する。コミット済みのAPIオブジェクトのRPOは0とする。

### 性能

性能はKubernetes v1.36.2と比較する。比較では、ハードウェア、オブジェクトのコーパス、リクエストのトレースを同じにする。

3 または 5 control node を構成でき、`floor((N-1)/2)` node の停止中も commit 済み state を失わない。
quorum 回復後 60 秒以内に API write、controller reconcile、scheduler bind を再開する。
commit 済み API object の RPO は 0 とする。

性能は同一 hardware、同一 object corpus、同一 request trace の Kubernetes v1.36.2 oracle と比較する。
steady state の API read/write、watch delivery、scheduling throughput の p99 latency は oracle の 2 倍以内、
error rate は oracle 以下とする。cached image の Native Pod start p95 は oracle の 2 倍以内、
base snapshot からの MicroVM start p95 は 1.5 秒以内とする。比較条件、warm-up、sample 数、
confidence interval、raw result を release artifact に保存する。

## Related

- [architecture](architecture.md)
- [kubernetes api](../api/kubernetes-api.md)
- [implementation plan](../delivery/implementation-plan.md)
