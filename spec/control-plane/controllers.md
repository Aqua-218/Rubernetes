[仕様書の目次](../README.md) / [制御面](README.md)

<a id="sec-5-5"></a>
# 5.5 コントローラ

> 対象読者: コントローラの実装者、Ruby DSLの設計者
>
> 状態: 規範、版0.2

組み込みのコントローラに共通する規約、主なコントローラの振る舞い、Controller DSLを定義する。

図は[図03 制御ループ](../diagrams/03-control-loop.md)にある。

<a id="sec-5-5-1"></a>
## 5.5.1 共通規約

すべてのコントローラは以下を満たす。

- C1: `reconcile(key)` は冪等である。同じ入力で何度呼んでも結果が同じ
- C2: 現在の状態のみから判断する。前回呼び出しの記憶を持たない
- C3: 差分のみを適用する。全削除・全再作成をしない
- C4: 自分が所有するリソースのみを変更する。所有は `ownerReference` で判定する
- C5: エラー時は例外を上位に返す。WorkQueue が再試行を担当する
- C6: v1.36.2 が持つ built-in controller の起動条件、feature gate、同期対象、status/event を compatibility corpus に登録する
- C7: corpus に存在する controller を未登録のまま起動してはならない

<a id="sec-5-5-2"></a>
## 5.5.2 DeploymentController

- Deployment の `spec.template` のハッシュで ReplicaSet を識別する
- RollingUpdate: `maxSurge` / `maxUnavailable` を満たす範囲で新旧の replicas を増減する
- 履歴を `revisionHistoryLimit` 件保持する
- `status` に `observedGeneration` を記録し、`spec.generation` と比較して進行を判定する

<a id="sec-5-5-3"></a>
## 5.5.3 ReplicaSetController

- 現存 Pod 数と `spec.replicas` の差だけ作成 / 削除する
- 削除優先度: 未スケジュール → Pending → 起動が新しい順
- 1 reconcile の作成上限は 500 Pod とし、slow-start batch を 1 から倍増する

<a id="sec-5-5-4"></a>
## 5.5.4 NodeController

- Node heartbeat の grace period は既定 40 秒とし、超過時に `Ready=Unknown` とする
- `Ready=Unknown` または `Ready=False` が既定 5 分継続した場合、対応する taint を付与する
- taint を許容しない Pod は退去対象とする

<a id="sec-5-5-5"></a>
## 5.5.5 EndpointController

- Service の `selector` に一致する Pod を集める
- `readiness` が真の Pod のみを `addresses` に載せる。偽は `notReadyAddresses`

<a id="sec-5-5-6"></a>
## 5.5.6 GarbageCollector

- 全リソースの `ownerReference` から所有グラフを構築する
- 所有者が消えた時、`propagationPolicy` に従い削除する
  - `Foreground`: 子を先に消してから親を消す
  - `Background`: 親を先に消し、子は非同期に消す
- 循環参照を検出した場合は削除せずイベントを記録する

<a id="sec-5-5-7"></a>
## 5.5.7 リーダー選出

controller-manager は複数起動しうる。
Lease リソースによるリーダー選出を行い、リーダーのみが reconcile する。
リーダーでない間はキャッシュのみ維持する。

<a id="sec-5-5-8"></a>
## 5.5.8 Controller DSL

Controller の配線は Ruby DSL で宣言し、Informer、Indexer、WorkQueue と reconcile を
[§5.5.1](controllers.md#sec-5-5-1) の規約に従って生成する。

```ruby
controller ReplicaSet do
  owns Pod
  watches Pod, via: :owner_reference

  reconcile do |rs|
    pods = owned_pods(rs)
    diff = rs.spec.replicas - pods.count(&:alive?)

    case diff
    when 1..  then create_pods(rs, diff)
    when ..-1 then delete_pods(pods, -diff)
    end
  end
end
```

`owns` は ownerReference index と GarbageCollector の ownership edge を登録する。
`watches` は GVR、event predicate、index lookup、queue key 変換を静的に確定する。
未登録 GVK、循環した ownership 宣言、scope が矛盾する watch は起動前に失敗させる。
DSL は配線を生成するだけであり、reconcile の C1〜C7 を緩和しない。

## Related

- [informer](informer.md)
- [Ruby Design index](../ruby/README.md)
- [03 control loop](../diagrams/03-control-loop.md)
