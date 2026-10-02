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

自作の実装と、隔離した比較対象に同じ入力を与え、観測できる結果を比べる。比較対象は、Kubernetes v1.36.2、etcd、runcとcontainerd、既存のCNIとCSIである。

比較対象のバイナリは、テスト用のイメージの中だけに置く。本番の成果物や本番の依存関係のグラフに混入した場合は、CIで拒否する。

結果が一致しなかった場合は、最小の反例に縮めて記録する。

差分テストは、[3.2](../foundation/architecture.md#sec-3-2)で差し替えの境界を設けた主な目的である。

<a id="sec-8-5"></a>
## 8.5 トレースの照合

実装の実行履歴を、TLA+の仕様の遷移の列として検査する。仕様が許さない遷移が観測された場合、原因は実装のバグか仕様の不足のどちらかである。両方を確認する。

<a id="sec-8-6"></a>
## 8.6 回帰

モデル検査、線形化の検査、差分テストで得た反例は、恒久的なテストとして固定する。CIで常に実行する。

<a id="sec-8-7"></a>
## 8.7 ランタイムの検証レベル

モックを使ったテストの成功を、隔離の境界の検証として扱ってはならない。ランタイムのテストには、次のレベルを明記する。

| レベル | 実行する対象 | 確かめられる範囲 |
|---|---|---|
| L0 Pure | 状態の遷移、設定の検証、ロールバックの計画 | 副作用が起きる前の決定性 |
| L1 Fake I/O | 障害を注入できるアダプタ | すべての分岐と、エラーの保持 |
| L2 Host integration | 実際のプロセス、ファイルシステム、Unixソケット | PIDの再利用、パス、フレーミング、後始末 |
| L3 Kernel isolation | 実際のnamespace、cgroup、seccomp、netlink、eBPF | kernelが境界を適用したという事実 |
| L4 KVM gate | 実際のFirecracker、jailer、dm-verity、vsock | microVMのライフサイクルと、ホスト側の後始末 |
| L5 Adversarial | 悪意のあるイメージ、ゲスト、ワークロードと、強制的なクラッシュ | fail-closedであることと、資源を再利用しないこと |

リリースは、x86_64のL3を通過しなければならない。x86_64でKVMを提供するランタイムについては、L4とL5も通過しなければならない。

ARMの実機プロファイルは、マイルストーンとリリースの完了条件に含めない。

<a id="sec-8-8"></a>
## 8.8 Kubernetesのupstreamテスト

Kubernetesのテストについて、次の項目は[Kubernetes v1.36.2互換性試験契約](kubernetes-compatibility.md)に従う。

- ソース
- ランナー
- テストの選択
- アーキテクチャとネットワークのプロファイル
- スキップを禁止する規則
- クライアントとプロジェクトのコーパス
- 証拠のスキーマ

Conformanceの成功だけを、完全な互換性の根拠としてはならない。同じ文書のK0〜K7をすべて通過する必要がある。

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
