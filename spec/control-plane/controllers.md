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

- Nodeのheartbeatのgrace periodは、既定で40秒とする。超えた場合は`Ready=Unknown`にする。
- `Ready=Unknown`または`Ready=False`が既定で5分続いた場合、対応するtaintを付ける。
- taintを許容しないPodは退去の対象とする。

<a id="sec-5-5-5"></a>
## 5.5.5 EndpointController

- Serviceの`selector`に一致するPodを集める。
- `readiness`が真のPodだけを`addresses`に載せる。偽のPodは`notReadyAddresses`に載せる。

<a id="sec-5-5-6"></a>
## 5.5.6 GarbageCollector

すべてのリソースの`ownerReference`から、所有関係のグラフを作る。

所有者が削除されたときは、`propagationPolicy`に従って子を削除する。

| ポリシー | 動作 |
|---|---|
| `Foreground` | 子を先に削除してから、親を削除する |
| `Background` | 親を先に削除する。子は非同期に削除する |

循環参照を検出した場合は、削除せずにイベントを記録する。

<a id="sec-5-5-7"></a>
## 5.5.7 リーダー選出

controller-managerは複数起動することがある。Leaseリソースでリーダーを選出し、リーダーだけがreconcileを行う。リーダーでないプロセスは、キャッシュの維持だけを行う。

<a id="sec-5-5-8"></a>
## 5.5.8 Controller DSL

コントローラの配線はRuby DSLで宣言する。DSLは、informer、Indexer、WorkQueue、reconcileを、[5.5.1](controllers.md#sec-5-5-1)の規約に従って生成する。

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

`owns`は、ownerReferenceのインデックスと、GarbageCollectorが使う所有関係の辺を登録する。

`watches`は、GVR、イベントの述語、インデックスの検索、キューのキーへの変換を静的に確定する。

次の宣言は、起動する前に失敗させる。

- 未登録のGVK
- 循環した所有関係
- scopeが矛盾するwatch

DSLは配線を生成するだけである。reconcileに対するC1〜C7の規約は緩めない。

## Related

- [informer](informer.md)
- [Ruby Design index](../ruby/README.md)
- [03 control loop](../diagrams/03-control-loop.md)
