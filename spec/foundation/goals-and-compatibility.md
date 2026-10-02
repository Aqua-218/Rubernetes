[仕様書の目次](../README.md) / [基礎](README.md)

<a id="sec-1"></a>
# 1. 目的とスコープ

> 対象読者: 全読者、審査者、アーキテクト
>
> 状態: 規範、版0.2


<a id="sec-1-1"></a>
## 1.1 目的

Kubernetes v1.36.2 と外部観測上互換な Linux コンテナオーケストレータを
Ruby で実装する。既存の Kubernetes マニフェスト、Helm chart、Operator、
クライアントライブラリおよび `kubectl` は、対象システム向けの変更なしに動作する。

Kubernetes から利用するものは API スキーマ、公開プロトコル、規範的な挙動、
適合試験および差分テストの期待値だけである。Kubernetes の実装コードは
本システムの実行経路へ組み込まない。API Server、Store、Raft、Controller、
Scheduler、Node Agent、コンテナランタイム、ネットワーク、Service Proxy、DNS、
Volume 管理は Ruby を中心に独立実装する。

<a id="sec-1-2"></a>
## 1.2 達成基準

| # | 基準 | 検証方法 |
|---|---|---|
| G1 | 本物の `kubectl` が接続し、`get` / `apply` / `delete` が通る | 実機で kubectl を実行 |
| G2 | 既存の Deployment マニフェストが無改変で動作する | 公開されている nginx Deployment を適用 |
| G3 | Pod がコンテナとして実際に隔離起動する | namespace / cgroup を実機で確認 |
| G4 | ノード障害時に Pod が別ノードで再作成される | 障害注入シナリオ |
| G5 | Raft の安全性が検証されている | 決定的な障害注入シミュレーションで TLA+ の不変条件が成立し、`LogMatching` は Lean で全 domain について証明。網羅的モデル検査は行わない（[7.2](../verification/formal-methods.md#sec-7-2) の実測により Raft では完了しないため） |
| G6 | 主要ロジックが Lean で証明されている | `sorry` ゼロ、CI で強制 |
| G7 | Kubernetes v1.36.2 の Linux Conformance と全 API 適合試験を通過する | upstream の固定済み test corpus を無変更で実行 |
| G8 | 既存の Helm chart と Operator が無変更で動く | 代表 corpus の install、upgrade、rollback、uninstall と reconcile を差分比較 |
| G9 | Native と MicroVM の両ランタイムが資源リークなく fail-closed する | 実機障害注入、再起動回復、TLA+ トレース照合 |
| G10 | プロジェクト固有の本番コードの 85% 以上を Ruby が占める | 生成物、vendor、fixture、TLA+、Lean、シェルを除外した LOC を CI で集計 |
| G11 | 1 個のスキーマ定義から型と全派生成物が一意に生成される | 再生成差分ゼロ、生成物相互整合テスト |

<a id="sec-1-3"></a>
## 1.3 互換性の境界

互換性の規範対象は Kubernetes v1.36.2 が Linux ノード向けに公開する次の境界である。

- すべての built-in API group/version/resource/subresource と CRD
- 既定および feature gate 有効時の defaulting、validation、conversion、admission
- JSON、YAML、Kubernetes Protobuf、watch、exec、attach、port-forward の wire protocol
- Controller、Scheduler、Node、Volume、Network、Service、DNS の外部観測可能な挙動
- `kubectl`、client-go、Dynamic Client、Helm および Operator から観測されるエラー契約

「互換」とは内部構造の一致ではなく、同一の前提状態と要求に対して、成功・失敗、
HTTP status、`Status.reason/details/causes`、defaulting 後のオブジェクト、field ownership、
イベント順序および最終的なクラスタ状態が一致することをいう。UID、時刻、乱数、
`resourceVersion`、ノード固有値は値そのものではなく、形式、単調性、一意性、因果順序を比較する。

Windows ノードと Windows コンテナは対象外とする。これは未実装機能ではなく、
Linux syscall、KVM、cgroup v2 を実行基盤とする本システムのプラットフォーム境界である。
Linux 上で実行可能な Kubernetes v1.36.2 の機能は段階や後続スコープへ退避させない。

<a id="sec-1-4"></a>
## 1.4 前提環境

- Linux kernel 6.12 以降（cgroup v2、OverlayFS、seccomp、Landlock、netlink、eBPF、KVM を使用）
- x86_64 または aarch64
- Ruby 3.4 以降
- Native backend は特権 bootstrap helper を起動後、専用非特権 UID へ降格する
- MicroVM backend は `/dev/kvm`、Firecracker 1.16.1 および同版の `jailer` を使用する
- cgroup v2 unified hierarchy、unprivileged user namespace、overlay、vxlan、br_netfilter、BPF を有効にする

<a id="sec-1-5"></a>
## 1.5 規模・可用性・性能

v1.36 の supported scale と同じく、1 cluster あたり 5,000 node、150,000 Pod、
300,000 container、1 node あたり 110 Pod を上限として扱う。この範囲内で API schema、
counter、queue、revision、identifier が overflow または意図しない hard limit に達してはならない。

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
