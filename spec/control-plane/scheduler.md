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

すべて満たすノードのみを候補とする。

- `NodeResourcesFit`: requests の合計が割当可能量以内
- `NodeName` / `NodeSelector` / `NodeAffinity`
- `TaintToleration`
- `PodAffinity` / `PodAntiAffinity`
- ノードが `Ready` であること

<a id="sec-5-6-3"></a>
## 5.6.3 Score

各項目 0〜100 で採点し、重み付き合計で選ぶ。

- `LeastAllocated`: 使用率が低いほど高得点
- `TopologySpread`: 同一トポロジ内の同一ラベル Pod が少ないほど高得点

同点の場合は決定的な規則で選ぶ（ノード名の辞書順）。
乱択を用いない。再現性が失われ、障害解析ができなくなるため。

<a id="sec-5-6-4"></a>
## 5.6.4 Bind

`Pod.spec.nodeName` を書き込む。
書き込みが失敗した場合、Reserve を巻き戻して再キューする。

<a id="sec-5-6-5"></a>
## 5.6.5 Preemption

Filter が全ノードで失敗し、Pod の優先度が既存 Pod より高い場合、
退去させる Pod の集合を求めて削除する。
退去対象が見つからない場合は `unschedulableQ` に入れる。

<a id="sec-5-6-6"></a>
## 5.6.6 Scheduler plugin DSL

Filter と Score は schema で型付けされた Pod/Node を受ける Ruby block として登録できる。

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
