[仕様書の目次](../README.md) / [制御面](README.md)

<a id="sec-5-6"></a>
# 5.6 スケジューラ

> 対象読者: スケジューラの実装者、形式検証の担当者
>
> 状態: 規範、版0.2

Filter、Score、Reserve、Bind、Preemptionと、Rubyで書くスケジューラプラグインのDSLを定義する。

図は[図03 制御ループ](../diagrams/03-control-loop.md)にある。

<a id="sec-5-6-1"></a>
## 5.6.1 手順

```text
SchedulingQueue → Filter → Score → Reserve → Bind
```

<a id="sec-5-6-2"></a>
## 5.6.2 Filter

次の条件をすべて満たすノードだけを候補にする。

- `NodeResourcesFit`: requestsの合計が、割り当て可能な量に収まる。
- `NodeName`、`NodeSelector`、`NodeAffinity`を満たす。
- `TaintToleration`を満たす。
- `PodAffinity`、`PodAntiAffinity`を満たす。
- ノードが`Ready`である。

<a id="sec-5-6-3"></a>
## 5.6.3 Score

各項目を0〜100で採点し、重みを付けた合計でノードを選ぶ。

| 項目 | 採点 |
|---|---|
| `LeastAllocated` | 使用率が低いほど高得点 |
| `TopologySpread` | 同じトポロジの中に同じラベルのPodが少ないほど高得点 |

同点の場合は、ノード名の辞書順という決定的な規則で選ぶ。乱数で選ぶと結果を再現できず、障害を解析できなくなる。そのため乱数は使わない。

<a id="sec-5-6-4"></a>
## 5.6.4 Bind

`Pod.spec.nodeName`を書き込む。書き込みに失敗した場合は、Reserveを取り消してPodをキューに戻す。

<a id="sec-5-6-5"></a>
## 5.6.5 Preemption

Filterがすべてのノードで失敗し、かつPodの優先度が既存のPodより高い場合に行う。退去させるPodの集合を求め、それらを削除する。

退去の対象が見つからない場合は、Podを`unschedulableQ`に入れる。

<a id="sec-5-6-6"></a>
## 5.6.6 スケジューラプラグインDSL

FilterとScoreは、Rubyのブロックとして登録できる。ブロックは、スキーマで型付けされたPodとNodeを受け取る。

```ruby
scheduler do
  filter :resources_fit do |pod, node|
    node.allocatable >= node.requested + pod.requests
  end

  score :least_allocated, weight: 1 do |pod, node|
    100 - node.utilization_percent
  end

  score :spread, weight: 2 do |pod, node|
    100 - same_topology_count(pod, node) * 10
  end
end
```

Filter は `true` または理由付き rejection、Score は 0〜100 の整数だけを返す。
範囲外、例外、非有限値、共有状態の変更を検出した plugin はその scheduling cycle を失敗させる。
plugin 名、実行順、weight、入力 snapshot digest、出力を trace に記録する。同点処理は
[§5.6.3](scheduler.md#sec-5-6-3) の決定的規則に従い、DSL から上書きできない。

## Related

- [controllers](controllers.md)
- [node agent](../node/node-agent.md)
- [formal methods](../verification/formal-methods.md)
