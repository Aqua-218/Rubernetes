[仕様書の目次](../README.md) / [検証](README.md)

<a id="sec-8"></a>
# 8. 検証

> **Audience:** テスト実装者、互換性検証者、セキュリティ検証者
>
> **Status:** Normative — version 0.2

test階層、障害注入DSL、線形化、差分test、trace照合、Runtime実機gateを定義する。


> **Diagram:** [図 08 — Verification](../diagrams/08-verification.md)

<a id="sec-8-1"></a>
## 8.1 テスト階層

| 層 | 対象 | 実行頻度 |
|---|---|---|
| 単体 | 関数・クラス | 毎コミット |
| プロパティ | 不変条件を満たすか | 毎コミット |
| 統合 | コンポーネント間 | 毎コミット |
| E2E | クラスタ全体 | 毎マージ |
| Kubernetes Conformance | v1.36.2定義446件、3 x86_64 release profile | main branch 日次、milestone candidate、release |
| 障害注入 | 分散・Runtime・MicroVM の安全性 | main branch 日次、release |
| モデル検査 | TLA+ 仕様 | 仕様変更時と release |
| 実機境界 | namespace/cgroup/seccomp/netlink/KVM/dm-verity/vsock | 対応 component 変更時、release |

<a id="sec-8-2"></a>
## 8.2 障害注入

| 種別 | 内容 |
|---|---|
| プロセス | SIGKILL、SIGSTOP、再起動、起動順の入れ替え |
| ネットワーク | 分断、非対称分断、遅延、ロス、並べ替え |
| ディスク | fsync 失敗、WAL の途中切断、領域枯渇 |
| 時計 | ずらし、巻き戻し |
| 資源 | メモリ逼迫、CPU 飽和 |
| Runtime | effect point ごとの失敗、応答消失、agent kill、kill 失敗、cleanup 失敗 |
| MicroVM | jailer kill、Firecracker hang、UDS 切断、pause ACK 消失、snapshot 破損、vsock 切断 |
| Identity | snapshot clone、CID/IP/UID 再利用要求、古い policy ACK、revoke と effect の競合 |

シナリオは Ruby DSL で記述し、単調時計上の注入と回復の時系列を制御する。

```ruby
scenario "leader loss during rollout" do
  setup { apply fixture("nginx-deployment") }

  timeline do
    at 0.seconds  { scale "web", to: 10 }
    at 3.seconds  { kill leader_node }
    at 10.seconds { heal }
  end

  assert_eventually(within: 60.seconds) { replicas_of("web") == 10 }
  assert_always { no_split_brain? }
end
```

`assert_eventually` は TLA+ の `◇`、`assert_always` は `□` に対応し、assertion 名、観測 predicate、
deadline、sampling/event trigger を trace metadata に残す。`assert_eventually` の deadline は必須、
`assert_always` は setup 完了から teardown 開始までの全 event 後に評価する。

<a id="sec-8-3"></a>
## 8.3 線形化可能性

- クライアント操作の履歴を invoke / ok / fail / info で記録する
- 逐次モデルは Lean から抽出した参照実装を用いる
- 探索で線形化順序を求める。存在しなければ違反として矛盾する操作対を提示する

<a id="sec-8-4"></a>
## 8.4 差分テスト

自作実装と隔離した oracle（Kubernetes v1.36.2、etcd、runc/containerd、既存 CNI/CSI）に
同一入力を与え、観測可能な結果を比較する。oracle binary は test image 内だけに置き、
production artifact と production dependency graph への混入を CI で拒否する。
不一致は最小反例に縮約して記録する。

これが [§3.2](../foundation/architecture.md#sec-3-2) で差し替え境界を設けた主目的である。

<a id="sec-8-5"></a>
## 8.5 トレース照合

実装の実行履歴を TLA+ 仕様の遷移列として検査する。
仕様が許さない遷移が観測された場合、
実装のバグか仕様の不足のいずれかであり、両方を確認する。

<a id="sec-8-6"></a>
## 8.6 回帰

モデル検査・線形化検査・差分テストで得た反例は、
恒久的なテストとして固定し、CI で常時実行する。

<a id="sec-8-7"></a>
## 8.7 Runtime 検証レベル

mock test の成功を隔離境界の検証として扱ってはならない。Runtime test は次の level を明記する。

| level | 実行対象 | 証明できる範囲 |
|---|---|---|
| L0 Pure | state transition、config validation、rollback plan | 副作用前の決定性 |
| L1 Fake I/O | failure injection 可能な adapter | 全 branch と error 保持 |
| L2 Host integration | 実 process、filesystem、Unix socket | PID reuse、path、framing、cleanup |
| L3 Kernel isolation | 実 namespace/cgroup/seccomp/netlink/eBPF | kernel が境界を適用した事実 |
| L4 KVM gate | 実 Firecracker/jailer/dm-verity/vsock | microVM lifecycle と host cleanup |
| L5 Adversarial | 悪性 image/guest/workload と強制 crash | fail-closed と resource non-reuse |

release は x86_64 の L3と、x86_64でKVMを提供するRuntimeのL4/L5を通過しなければならない。
ARM実機profileはmilestoneまたはreleaseの完了条件に含めない。

<a id="sec-8-8"></a>
## 8.8 Kubernetes upstream test

Kubernetes testのsource、runner、selection、architecture/network profile、skip禁止規則、
client/project corpus、evidence schemaは
[Kubernetes v1.36.2互換性試験契約](kubernetes-compatibility.md)に従う。
Conformanceの成功だけを完全互換の根拠としてはならず、同文書のK0〜K7をすべて通過する。

upstream sourceをRubernetes向けにpatchしたtest、failure後にfocusして再実行したtest、
未実装機能をskipしたtestは互換性evidenceへ算入しない。

## Related

- [formal methods](formal-methods.md)
- [kubernetes compatibility](kubernetes-compatibility.md)
- [kubernetes api](../api/kubernetes-api.md)
- [milestones](../delivery/milestones.md)
