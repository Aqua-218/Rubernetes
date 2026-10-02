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

すべてのコントローラは次の規約を満たす。

| 番号 | 規約 |
|---|---|
| C1 | `reconcile(key)`は冪等である。同じ入力で何度呼んでも結果が変わらない |
| C2 | 現在の状態だけから判断する。前回の呼び出しの記憶を持たない |
| C3 | 差分だけを適用する。すべて削除して作り直すことはしない |
| C4 | 自分が所有するリソースだけを変更する。所有は`ownerReference`で判定する |
| C5 | エラーが起きたら例外を上位に返す。再試行はWorkQueueが受け持つ |
| C6 | v1.36.2が持つ組み込みのコントローラについて、起動条件、feature gate、同期の対象、statusとeventを互換性コーパスに登録する |
| C7 | コーパスにあるコントローラを、未登録のまま起動してはならない |

<a id="sec-5-5-2"></a>
## 5.5.2 DeploymentController

- Deploymentの`spec.template`のハッシュでReplicaSetを識別する。
- RollingUpdateでは、`maxSurge`と`maxUnavailable`を満たす範囲で、新旧のreplicasを増減する。
- 履歴を`revisionHistoryLimit`件保持する。
- `status`に`observedGeneration`を記録する。`spec.generation`と比較して進行を判定する。

<a id="sec-5-5-3"></a>
## 5.5.3 ReplicaSetController

- 現在のPod数と`spec.replicas`の差の分だけ、Podを作成または削除する。
- 削除するPodは次の優先順で選ぶ。まだスケジュールされていないPod、PendingのPod、起動が新しいPodの順である。
- 1回のreconcileで作成するPodは500個までとする。slow-startのバッチは1個から始めて倍に増やす。

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
