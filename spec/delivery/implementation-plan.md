[仕様書インデックス](../README.md) / [delivery](README.md)

<a id="sec-9"></a>
# 9. 実装順

> **Audience:** 実装者、project管理者、審査者
>
> **Status:** Normative — version 0.3

全MUST要件を完成させる実装順、固定済み設計判断、release gateを定義する。


段階は実装順だけを表し、最終スコープを分割または任意化しない。各段階の終了時に、
それまでの vertical slice、生成物、形式仕様、回帰 test が同時に動作する状態を保つ。
[マイルストーン](milestones.md)は本stageをM0〜M9へ束ね、各境界の成果物、exit criteria、
machine-readable evidenceを追加定義する。両文書が衝突する場合は、より強い完了条件を適用する。

| 段階 | 到達点 | 主な検証 |
|---|---|---|
| 00 | Ruby FFI、ABI generator、clone3/pidfd/mount/netlink/bpf/KVM capability probe | x86_64実kernel smoke |
| 01 | v1.36.2 corpus、schema DSL/compiler、Ruby type/codec/OpenAPI/RBS/manifest DSL | 再生成差分ゼロ、全 GVK round-trip |
| 02 | API Server + MemoryStore、discovery、CRUD/watch/patch/apply | `kubectl` と API differential |
| 03 | Native sandbox、image、namespace、OverlayFS、cgroup、seccomp、process gate | Runtime L0〜L3、resource leak zero |
| 04 | Node Agent と 1 node Pod lifecycle を端から端まで貫通 | init/sidecar/probe/restart/terminate E2E |
| 05 | Controller DSL、Deployment → ReplicaSet → Pod | 冪等性、ownership、rollout differential |
| 06 | Informer と v1.36.2 built-in controller 全体 | event 欠落、全 controller corpus 登録 |
| 07 | Scheduler DSL、全標準 plugin、preemption、複数 node | Filter/Score Lean、配置 differential |
| 08 | Native Network、IPAM、VXLAN、NetworkPolicy、DNS、eBPF/nftables Proxy | Pod/Service/Ingress/Egress E2E |
| 09 | Volume、PV/PVC/StorageClass、snapshot、CSI protocol | mount attack、attach race、storage E2E |
| 10 | RaftStore、WAL、snapshot、membership | TLA+、crash recovery、線形化可能性 |
| 11 | 全認証/認可/admission、CRD、aggregation、全 API/subresource | v1.36.2 API corpus 差分ゼロ |
| 12 | Firecracker/jailer、Ruby guest supervisor、standard/restricted MicroVM | Runtime L0〜L5、identity non-reuse |
| 13 | 全 component の durable ownership、rollback、crash recovery | 全 effect point fault matrix |
| 14 | Conformance、Helm/Operator corpus、障害 DSL、trace/model/proof bridge | upstream 無改変 test、反例固定 |
| 15 | 性能、長時間試験、供給網固定、release artifact | [§9.3](implementation-plan.md#sec-9-3) release gate 全項目 |

<a id="sec-9-1"></a>
## 9.1 段階 00 の完了条件

- Ruby から `clone3(2)` を FFI 経由で呼び、`CLONE_NEWPID | CLONE_NEWNS | CLONE_PIDFD` を指定できる
- 子プロセス内で `/proc` を再マウントし、`ps` が自プロセスのみを表示する
- 親が pidfd で子の終了を待ち、PID 再利用と混同せず終了コードを取得できる
- 失敗時に `errno` を正しく取得できる
- x86_64のstruct size、alignment、syscall numberをkernel header由来manifestと照合できる
- netlink ACK、BPF verifier log、`/dev/kvm` capability を Ruby から取得できる

この段階が通らなければ以降の設計が成立しない。最優先で確認する。

<a id="sec-9-2"></a>
## 9.2 固定済み設計判断

| ID | 決定 |
|---|---|
| D1 | User namespace は `hostUsers=false` の Pod 単位で共有し、既定の `hostUsers=true` は Kubernetes 互換を維持する |
| D2 | Raft batch は 256 entry/1 MiB/2 ms、snapshot は 100,000 entry または WAL 512 MiB とする |
| D3 | Proxy は eBPF と nftables の両 backend を実装し、capability probe で自動選択する |
| D4 | Lean 抽出物は test oracle に限定し、本番 Ruby 実装と differential property test で結ぶ |
| D5 | CRD、dynamic registration、conversion、OpenAPI publish は release 必須要件とする |
| D6 | Native を既定、MicroVM と MicroVMRestricted を標準 RuntimeClass とする |
| D7 | rootless は user namespace と専用 helper の最小特権分離として実装し、特権処理を agent 本体へ置かない |

<a id="sec-9-3"></a>
## 9.3 release 完了条件

次の全項目を満たすまで `1.0.0`、完成、完全互換を名乗ってはならない。

- v1.36.2 discovery/OpenAPI/protobuf/API behavior corpus の未実装項目が 0
- upstream v1.36.2 Linux Conformance 446件の失敗/skip 0、再試行によってだけ成功する flaky test 0
- platform allowlist 以外の skip 0
- Native、MicroVM、MicroVMRestricted が対応する Runtime L0〜L5 gate を通過
- built-in controller、scheduler plugin、CRD、CSI、NetworkPolicy、eBPF/nftables Proxy が E2E を通過
- すべての effect point で crash/response-loss を注入し、live resource の誤解放と identity 再利用が 0
- TLA+ release scope で反例 0、Lean の `sorry` / `admit` / 禁止 escape hatch 0
- schema 生成差分、RBS、OpenAPI、codec、patch field 集合の不一致 0
- compatibility corpus の Helm chart/Operator を変更なしで install/upgrade/rollback/uninstall 可能
- [Kubernetes互換性試験契約](../verification/kubernetes-compatibility.md)のK0〜K7を全profileで通過
- project-authored production source の Ruby 比率 85% 以上
- 未決マーカー、期限のない作業注記、保証レベル未記載の security claim 0

## Related

- [coding standards](coding-standards.md)
- [milestones](milestones.md)
- [project structure](project-structure.md)
- [goals and compatibility](../foundation/goals-and-compatibility.md)
- [kubernetes compatibility](../verification/kubernetes-compatibility.md)
