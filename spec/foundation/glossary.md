[仕様書の目次](../README.md) / [基礎](README.md)

<a id="sec-2"></a>
# 2. 用語

> 対象読者: 全読者
>
> 状態: 規範、版0.2

本仕様全体で使うKubernetes、ランタイム、形式検証の用語を定義する。

| 用語 | 定義 |
|---|---|
| リソース | APIサーバが管理する宣言的なオブジェクト。Pod、Deploymentなど |
| GVK | Group、Version、Kindの組。リソースの型を識別する |
| GVR | Group、Version、Resourceの組。RESTパス上でリソースを識別する |
| desired state | マニフェストが表す、あるべき状態 |
| actual state | 実際に観測された状態 |
| reconcile | desired stateとactual stateの差を埋める操作。冪等でなければならない |
| resourceVersion | ストアが採番する単調増加のリビジョン。楽観ロックに使う |
| 収束 | reconcileを繰り返した結果、actual stateがdesired stateに一致すること |
| ノード | ワーカーを実行する1台のホスト |
| サンドボックス | Pod単位で共有されるnamespaceの集合 |
| Native backend | RubyがLinuxのシステムコールを直接発行してPodを隔離する、既定のランタイム |
| MicroVM backend | RubyがFirecrackerを制御し、1つのPodを1つのmicroVMに隔離するランタイム |
| compatibility oracle | 差分テストでだけ使う比較対象。Kubernetes v1.36.2または既存の実装を指す |
| effect point | 管理対象の外部状態が初めて変化しうる地点。システムコール、変更を伴うAPI呼び出し、永続化など |
| owned resource | サンドボックスが排他的に取得したOS資源。解放が完了するまで所有権を追跡する |
| ambiguous state | 要求の成否を観測できず、成功とも失敗とも断定できない状態 |

## 関連

- [document conventions](document-conventions.md)
- [architecture](architecture.md)
- [runtime](../node/runtime.md)
