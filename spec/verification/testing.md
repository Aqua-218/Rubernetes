[仕様書の目次](../README.md) / [検証](README.md)

<a id="sec-8"></a>
# 8. 検証

> 対象読者: テストの実装者、互換性の検証者、セキュリティの検証者
>
> 状態: 規範、版0.2

テストの階層、障害注入のDSL、線形化、差分テスト、トレースの照合、ランタイムの実機でのゲートを定義する。

図は[図08 検証](../diagrams/08-verification.md)にある。

<a id="sec-8-1"></a>
## 8.1 テスト階層

| 層 | 対象 | 実行する頻度 |
|---|---|---|
| 単体 | 関数とクラス | 毎コミット |
| property | 不変条件を満たすかどうか | 毎コミット |
| 統合 | コンポーネントの間 | 毎コミット |
| e2e | クラスタ全体 | 毎マージ |
| Kubernetes Conformance | v1.36.2が定義する446件。x86_64の3つのリリースプロファイルで実行する | mainブランチで毎日、マイルストーンの候補、リリース |
| 障害注入 | 分散処理、ランタイム、MicroVMの安全性 | mainブランチで毎日、リリース |
| モデル検査 | TLA+の仕様 | 仕様の変更時、リリース |
| 実機の境界 | namespace、cgroup、seccomp、netlink、KVM、dm-verity、vsock | 対応するコンポーネントの変更時、リリース |

<a id="sec-8-2"></a>
## 8.2 障害注入

| 種別 | 内容 |
|---|---|
| プロセス | SIGKILL、SIGSTOP、再起動、起動順の入れ替え |
| ネットワーク | 分断、非対称な分断、遅延、ロス、並べ替え |
| ディスク | fsyncの失敗、WALの途中での切断、領域の枯渇 |
| 時計 | ずらし、巻き戻し |
| 資源 | メモリの逼迫、CPUの飽和 |
| ランタイム | effect pointごとの失敗、応答の喪失、agentのkill、killの失敗、後始末の失敗 |
| MicroVM | jailerのkill、Firecrackerのハング、UDSの切断、pause ACKの喪失、スナップショットの破損、vsockの切断 |
| identity | スナップショットのクローン、CID・IP・UIDの再利用の要求、古いポリシーのACK、失効とeffectの競合 |

シナリオはRuby DSLで書く。単調時計の上で、障害の注入と回復の時系列を制御する。

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

`assert_eventually`はTLA+の`◇`に対応する。`assert_always`は`□`に対応する。

トレースのメタデータには、アサーションの名前、観測する述語、期限、サンプリングまたはイベントによる起動条件を残す。

`assert_eventually`では期限の指定を必須とする。`assert_always`は、setupの完了からteardownの開始までの間、すべてのイベントのあとに評価する。

<a id="sec-8-3"></a>
## 8.3 線形化可能性

- クライアントの操作の履歴を、invoke、ok、fail、infoで記録する。
- 逐次モデルには、Leanから抽出した参照実装を使う。
- 探索によって線形化の順序を求める。順序が存在しなければ違反とし、矛盾する操作の対を示す。

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
