[仕様書の目次](../README.md) / [API](README.md)

<a id="sec-5-1"></a>
# 5.1 APIサーバ

> 対象読者: APIサーバの実装者、セキュリティの設計者
>
> 状態: 規範、版0.2

APIリクエストの処理順序、認証、認可、流量制御、admission、監査、保存時の暗号化を定義する。

図は[図01 APIサーバ](../diagrams/01-api-server.md)にある。

<a id="sec-5-1-1"></a>
## 5.1.1 処理順序

リクエストは次の順に処理する。この順序を変更してはならない。

1. TLSの終端
2. リクエストIDの付与
3. 認証（[5.1.2](api-server.md#sec-5-1-2)）
4. 認可（[5.1.3](api-server.md#sec-5-1-3)）
5. 流量制御（[5.1.4](api-server.md#sec-5-1-4)）
6. ルーティングとGVRの解決
7. デコード（[5.1.5](api-server.md#sec-5-1-5)）
8. mutating admission
9. validating admission
10. strategy（defaultingと正規化）
11. ストアの操作
12. エンコードと応答
13. 監査の記録

認可をadmissionより前に置く。権限のない要求でadmissionの副作用が起きることを防ぐためである。

<a id="sec-5-1-2"></a>
## 5.1.2 認証

次の認証器を実装する。

- x509クライアント証明書
- ServiceAccountの署名付きJWTとTokenRequest
- OIDC
- webhook token authenticator
- bootstrap token
- request-headerによるプロキシ認証
- 静的なトークンファイル

未認証は `401` と `WWW-Authenticate` を返す。匿名認証の既定値と endpoint ごとの扱いは
v1.36.2 の structured authentication configuration に従う。token、証明書、認証 header、
ServiceAccount Secret はログ、trace、Event、例外 message に出力してはならない。

<a id="sec-5-1-3"></a>
## 5.1.3 認可

RBAC、Node、Webhook、ABAC および AlwaysAllow/AlwaysDeny authorizer を実装し、
設定された順に union 評価する。既定構成は Node,RBAC とする。評価規則:

- 適用可能な Role / ClusterRole の中に 1 つでも許可があれば許可
- 明示的な拒否ルールは持たない（Kubernetes に合わせる）
- 未認可は `403`

<a id="sec-5-1-4"></a>
## 5.1.4 流量制御

- FlowSchema と PriorityLevelConfiguration で要求を分類し、shuffle sharding した seat queue を持つ
- 既定は 64 queue、hand size 8、queue length limit 50、request wait limit 60 秒とする
- 短時間 read は 400 seat、mutating は 200 seat を既定上限とし、APF の seat 配分を適用する
- 待機上限または queue 上限を超えた要求は `429` と `Retry-After` を返す
- watch は長時間接続のため実行中カウントから除外する

<a id="sec-5-1-5"></a>
## 5.1.5 Scheme / Codec

- GVK と Ruby クラスの対応をレジストリで一元管理する
- external version、internal hub version、storage version 間の conversion graph を保持する
- JSON、YAML、CBOR、Kubernetes Protobuf と内部表現の変換を一箇所に集約する
- built-in field の unknown-field pruning、strict validation、warning は `fieldValidation` に従う
- CRD の未知フィールド保持は `x-kubernetes-preserve-unknown-fields` に従う
- lossless conversion が定義された version 間では external → hub → external の情報保存を property test で強制する

<a id="sec-5-1-6"></a>
## 5.1.6 削除と finalizer

1. `DELETE` を受けたら `metadata.deletionTimestamp` を設定する
2. `finalizers` が空でない限り、オブジェクトは削除しない
3. 各 finalizer の担当コントローラが後始末後に自分の項目を除去する
4. `finalizers` が空になった時点で実削除する

猶予期間（`gracePeriodSeconds`）の既定値は Pod で 30 秒。

<a id="sec-5-1-7"></a>
## 5.1.7 Admission と API 拡張

v1.36.2 の built-in mutating/validating admission plugin、MutatingAdmissionWebhook、
ValidatingAdmissionWebhook、ValidatingAdmissionPolicy/CEL を feature corpus に従って実装する。
webhook の matchPolicy、namespace/object selector、matchConditions、failurePolicy、sideEffects、
reinvocationPolicy、timeoutSeconds、version negotiation、warning を同じ順序と条件で評価する。

Mutating phase は再呼出しを含む最終 object を確定してから Validating phase へ進む。
webhook timeout の既定は 10 秒、API が許す上限は 30 秒とし、timeout/通信失敗時は failurePolicy に従う。
dry-run request では sideEffects が `None` または `NoneOnDryRun` でない webhook を呼び出さない。

CRD conversion webhook と API aggregation proxy は mTLS で peer identity を検証し、request body 3 MiB、
応答 3 MiB、接続 30 秒を上限とする。aggregated API の discovery/OpenAPI/health は built-in と統合し、
同一 GVR の競合を起動時または登録 transaction 内で拒否する。

<a id="sec-5-1-8"></a>
## 5.1.8 監査と保存時暗号化

監査は RequestReceived、ResponseStarted、ResponseComplete、Panic stage を policy に従って記録する。
token、Authorization header、client key、Secret data、exec/attach stream body を記録してはならない。
監査 sink の停止は API write を無条件に停止させず、bounded queue 超過を metric/Event と durable local log に残す。

Secret、ServiceAccount token、bootstrap credential と指定 API field は envelope encryption する。
組込み provider は AES-256-GCM、外部 provider は Kubernetes KMS v2 protocol とし、data encryption key を
object ごとに生成する。nonce は key ごとに再利用せず、暗号化失敗時に plaintext を Store/WAL/snapshot へ
書いてはならない。key rotation は旧 key で read、新 key で write し、background rewrite 後に旧 key を廃止する。

## Related

- [kubernetes api](kubernetes-api.md)
- [store](../control-plane/store.md)
- [01 api server](../diagrams/01-api-server.md)
