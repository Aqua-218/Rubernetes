[仕様書インデックス](../README.md) / [foundation](README.md)

<a id="sec-2"></a>
# 2. 用語

> **Audience:** 全読者
>
> **Status:** Normative — version 0.2

本仕様全体で使用する Kubernetes、Runtime、形式検証の用語を一意に定義する。


| 用語 | 定義 |
|---|---|
| リソース | API サーバが管理する宣言的オブジェクト。Pod、Deployment 等 |
| GVK | Group / Version / Kind の組。リソース型の識別子 |
| GVR | Group / Version / Resource の組。REST パス上の識別子 |
| desired state | マニフェストが表す、あるべき状態 |
| actual state | 実際に観測された状態 |
| reconcile | desired と actual の差分を埋める操作。冪等でなければならない |
| resourceVersion | ストアが採番する単調増加のリビジョン。楽観ロックに使う |
| 収束 | reconcile の反復により actual が desired に一致すること |
| ノード | ワーカーを実行する 1 台のホスト |
| サンドボックス | Pod 単位で共有される namespace の集合 |
| Native backend | Ruby が Linux syscall を直接発行して Pod を隔離する既定ランタイム |
| MicroVM backend | Ruby が Firecracker を制御し、1 Pod を 1 microVM に隔離するランタイム |
| compatibility oracle | Kubernetes v1.36.2 または既存実装を、差分テストでのみ使う比較対象 |
| effect point | syscall、mutating API、永続化など、管理対象の外部状態が初めて変化し得る地点 |
| owned resource | sandbox が排他的に取得し、解放完了まで所有権を追跡する OS 資源 |
| ambiguous state | 要求の成否を観測できず、成功とも失敗とも断定できない状態 |

## Related

- [document conventions](document-conventions.md)
- [architecture](architecture.md)
- [runtime](../node/runtime.md)
