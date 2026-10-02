[仕様書の目次](../README.md) / [制御面](README.md)

<a id="sec-5-4"></a>
# 5.4 informer

> 対象読者: 制御ループの実装者
>
> 状態: 規範、版0.2

Reflector、DeltaFIFO、Indexer、WorkQueueの接続を定義する。イベントと再試行についての不変条件も定める。

図は[図03 制御ループ](../diagrams/03-control-loop.md)にある。

<a id="sec-5-4-1"></a>
## 5.4.1 構成

```text
Reflector → DeltaFIFO → Indexer → EventHandler → WorkQueue
```

<a id="sec-5-4-2"></a>
## 5.4.2 要件

| 番号 | 要件 |
|---|---|
| I1 | 起動時にlistを行い、得られた`resourceVersion`からwatchを始める。その間にイベントを落とさない |
| I2 | watchが切断されたら、指数バックオフで再接続する。`410 Gone`が返った場合はlistをやり直す |
| I3 | `ResyncPeriod`ごとに、キャッシュの全内容をSyncイベントとして再投入する。既定値は10分である |
| I4 | WorkQueueは同じキーの重複を取り除く。処理中に同じキーが再投入された場合は、処理が終わったあとに1回だけ再処理する |
| I5 | 処理に失敗したキーは再投入する。再投入の間隔は、5 msから1,000秒までの指数バックオフとtoken bucketを組み合わせて決める。キーを恒久的に捨てることはしない。成功するか対象が消えるまで、dirty keyとして保持する |

<a id="sec-5-4-3"></a>
## 5.4.3 キャッシュの不変性

Indexerが返したオブジェクトを、呼び出し側が変更してはならない。

キャッシュはすべてのコントローラが共有している。1か所で破壊的に変更すると、無関係なコントローラの判断まで誤らせる。そのため、オブジェクトは返すときにfreezeする。コーディング規約のR-4.2に対応する。

## 関連

- [controllers](controllers.md)
- [kubernetes api](../api/kubernetes-api.md)
- [03 control loop](../diagrams/03-control-loop.md)
