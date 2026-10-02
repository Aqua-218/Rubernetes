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

複数の認証器が返したuser、group、extraが矛盾する場合は、要求を拒否する。

認証されていない要求には、`401`と`WWW-Authenticate`を返す。匿名認証の既定値と、エンドポイントごとの扱いは、v1.36.2のstructured authentication configurationに従う。

トークン、証明書、認証ヘッダ、ServiceAccountのSecretを、ログ、トレース、Event、例外のメッセージに出力してはならない。

<a id="sec-5-1-3"></a>
## 5.1.3 認可

RBAC、Node、Webhook、ABAC、AlwaysAllow、AlwaysDenyの各authorizerを実装する。設定された順に評価し、結果を合わせて判定する。既定の構成は`Node,RBAC`とする。

評価の規則は次のとおりである。

- 適用できるRoleとClusterRoleの中に許可が1つでもあれば、許可する。
- 明示的な拒否のルールは持たない。Kubernetesに合わせるためである。
- 認可されなかった要求には`403`を返す。

<a id="sec-5-1-4"></a>
## 5.1.4 流量制御

FlowSchemaとPriorityLevelConfigurationで要求を分類する。キューはseat単位で管理し、shuffle shardingで要求を振り分ける。

| 項目 | 既定値 |
|---|---|
| キューの数 | 64 |
| hand size | 8 |
| キュー長の上限 | 50 |
| 要求の待ち時間の上限 | 60秒 |
| 短時間の読み取りのseat上限 | 400 |
| 変更を伴う要求のseat上限 | 200 |

seatの配分にはAPFの規則を適用する。

待ち時間の上限かキューの上限を超えた要求には、`429`と`Retry-After`を返す。

watchは長時間の接続なので、実行中の数には含めない。

<a id="sec-5-1-5"></a>
## 5.1.5 スキームとコーデック

- GVKとRubyのクラスの対応を、レジストリで一元管理する。
- 外部バージョン、内部のhubバージョン、保存バージョンの間のconversionグラフを保持する。
- JSON、YAML、CBOR、Kubernetes Protobufと内部表現との変換を、1か所に集約する。
- 組み込みのフィールドについて、未知のフィールドのpruning、strict validation、warningは`fieldValidation`に従う。
- CRDで未知のフィールドを保持するかどうかは、`x-kubernetes-preserve-unknown-fields`に従う。
- 情報を失わないconversionが定義されたバージョンの間では、外部、hub、外部と変換しても情報が保存されることを、property testで強制する。

<a id="sec-5-1-6"></a>
## 5.1.6 削除とfinalizer

1. `DELETE`を受けたら、`metadata.deletionTimestamp`を設定する。
2. `finalizers`が空でない間は、オブジェクトを削除しない。
3. 各finalizerを担当するコントローラが後始末をし、自分の項目を取り除く。
4. `finalizers`が空になった時点で、実際に削除する。

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
