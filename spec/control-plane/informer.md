[仕様書の目次](../README.md) / [制御面](README.md)

<a id="sec-5-4"></a>
# 5.4 informer

> **Audience:** 制御ループ実装者
>
> **Status:** Normative — version 0.2

Reflector、DeltaFIFO、Indexer、WorkQueueの接続とevent/retry不変条件を定義する。


> **Diagram:** [図 03 — 制御ループ](../diagrams/03-control-loop.md)

<a id="sec-5-4-1"></a>
## 5.4.1 構成

```text
Reflector → DeltaFIFO → Indexer → EventHandler → WorkQueue
```

<a id="sec-5-4-2"></a>
## 5.4.2 要件

- I1: 起動時に list し、その `resourceVersion` から watch を開始する。この間にイベントを落とさない
- I2: watch 切断時は指数バックオフで再接続する。`410 Gone` なら再 list する
- I3: `ResyncPeriod` の既定 10 分ごとに全キャッシュを Sync イベントとして再投入する
- I4: WorkQueue は同一キーの重複を排除する。処理中に同キーが再投入された場合、処理完了後に一度だけ再処理する
- I5: 処理失敗時は 5 ms から 1,000 秒までの指数 backoff と token bucket を組み合わせて再投入する。恒久破棄せず、成功または対象消滅まで dirty key を保持する

<a id="sec-5-4-3"></a>
## 5.4.3 キャッシュの不変性

Indexer が返すオブジェクトを呼び出し側が変更してはならない。
キャッシュは全コントローラで共有されるため、
1 箇所の破壊的変更が無関係なコントローラの判断を狂わせる。
返却時に freeze する（規約 R-4.2）。

## Related

- [controllers](controllers.md)
- [kubernetes api](../api/kubernetes-api.md)
- [03 control loop](../diagrams/03-control-loop.md)
