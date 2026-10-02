[仕様書の目次](../README.md) / [API](README.md)

<a id="sec-4"></a>
# 4. API仕様

> 対象読者: API実装者、クライアントの作者、互換性の検証者
>
> 状態: 規範、版0.2

Kubernetes v1.36.2に対するリソース、エンドポイント、ワイヤ形式、watch、patch、互換性の判定を定義する。

<a id="sec-4-1"></a>
## 4.1 対象リソース

対象は、Kubernetesの`v1.36.2`タグが配布する次の情報に現れるすべてのリソースである。

- discovery
- OpenAPI v2とv3
- Protocol Bufferの定義
- APIのライフサイクル情報

リソースの一覧は本文に複製しない。次の機械可読なコーパスを規範とする。

| コーパス | 内容 | 更新の規則 |
|---|---|---|
| `schema/kubernetes/v1.36.2/discovery/` | group、version、resource、scope、verb、shortName、category、subresource | upstreamの応答を正規化して固定する |
| `schema/kubernetes/v1.36.2/openapi/` | フィールド、型、required、既定値、validation、patch strategy | upstreamの配布物のSHA-256を固定する |
| `schema/kubernetes/v1.36.2/protobuf/` | ワイヤ上のフィールド番号とメッセージの定義 | upstreamの`.proto`とdescriptor setを固定する |
| `schema/kubernetes/v1.36.2-defaults/features.json` | feature gate、既定値、対象のAPI | すべてのgateについてon、offのプロファイルを生成する |
| upstreamの`test/conformance/testdata/conformance.yaml` | 規範となるAPIとe2eの挙動 | upstreamのテスト一覧を変更せず、`third_party/locks/kubernetes-v1.36.2.json`でダイジェストを固定する |

CRDを登録した場合は、組み込みのリソースと同じ経路で扱う。対象は、提供するバージョン、subresource、conversion、defaulting、CELによるvalidation、selectable field、printer column、OpenAPIの公開、discoveryへの反映である。

コーパスに新しいGVKを追加したときは、[6.2](../ruby/schema-compiler.md#sec-6-2)の生成処理が次のものを同時に生成しなければならない。

- 型
- コーデック
- validation
- DSL
- RBS
- OpenAPI
- 差分計算

<a id="sec-4-2"></a>
## 4.2 エンドポイント

### リソースのエンドポイント

core groupは`/api/{version}`を基点とする。名前付きのgroupは`/apis/{group}/{version}`を基点とする。

各GVRのscopeとverbはdiscoveryのコーパスに従う。エンドポイントは次のテンプレートから機械的に生成する。

```text
GET    {base}/{resource}                                      list
GET    {base}/{resource}?watch=true                           watch
POST   {base}/{resource}                                      create
DELETE {base}/{resource}                                      deletecollection
GET    {base}/{resource}/{name}                               get
PUT    {base}/{resource}/{name}                               replace
PATCH  {base}/{resource}/{name}                               patch / apply
DELETE {base}/{resource}/{name}                               delete
GET    {base}/{resource}/{name}/{subresource}                 get subresource
PUT    {base}/{resource}/{name}/{subresource}                 update subresource
PATCH  {base}/{resource}/{name}/{subresource}                 patch subresource
```

namespaceに属するリソースでは、`{base}`は`.../namespaces/{namespace}`になる。すべてのnamespaceを対象にしたlistとwatchは、group/versionの直下で受け付ける。

### PATCH

PATCHは次の形式をすべて実装する。

| Content-Type | 意味 |
|---|---|
| `application/json-patch+json` | RFC 6902のJSON Patch |
| `application/merge-patch+json` | RFC 7386のJSON Merge Patch |
| `application/strategic-merge-patch+json` | スキーマのpatch strategyを使うStrategic Merge Patch |
| `application/apply-patch+yaml` | Server-Side Apply |
| `application/apply-patch+cbor` | CBORによるapply。対応するfeature gateが無効なときは、upstreamと同じように拒否する |

### クエリパラメータ

list、watch、deletecollectionは、次のパラメータを受け付ける。validationと意味はv1.36.2と同じにする。

- `labelSelector`
- `fieldSelector`
- `limit`
- `continue`
- `resourceVersion`
- `resourceVersionMatch`
- `timeoutSeconds`
- `allowWatchBookmarks`
- `sendInitialEvents`

### 補助エンドポイント

```text
GET /version                                      VersionInfo
GET /api                                          APIVersions
GET /apis                                         APIGroupList / aggregated discovery
GET /api/{version}                                APIResourceList
GET /apis/{group}/{version}                       APIResourceList
GET /openapi/v2                                   OpenAPI v2
GET /openapi/v3                                   OpenAPI v3 discovery
GET /openapi/v3/apis/{group}/{version}            group/version OpenAPI v3
GET /healthz  /livez  /readyz                     ヘルスチェック
```

`kubectl`は起動時に、`/api`、`/apis`、`APIResourceList`といったdiscovery系のエンドポイントを必ず呼ぶ。discoveryが正しく返らないと、以降の操作はすべて失敗する。そのため、実装順ではdiscoveryを最優先とする。

### subresourceとプロトコル

`exec`、`attach`、`portforward`、`log`、`proxy`、`eviction`、`binding`、`scale`、`status`、`token`、`approval`などのsubresourceは、discoveryコーパスのverbと、Kubernetesのストリーミングプロトコルに従う。

content negotiationでは次のものを選択できる。

- HTTP/1.1、HTTP/2、WebSocket、SPDYへのフォールバック
- JSON、YAML、Kubernetes Protobuf
- gzip

<a id="sec-4-3"></a>
## 4.3 レスポンス形式

### オブジェクト

すべてのリソースは、`apiVersion`、`kind`、スキーマが指定するmetadataを持つ。`spec`と`status`は、そのGVKのスキーマにある場合だけ持つ。次はPodの例である。

```json
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "...", "namespace": "...", "uid": "...",
    "resourceVersion": "...", "creationTimestamp": "...",
    "labels": {}, "annotations": {},
    "ownerReferences": [], "finalizers": [],
    "deletionTimestamp": null
  },
  "spec": {},
  "status": {}
}
```

list は対応する List kind、`metadata.resourceVersion`、`continue`、
`remainingItemCount` および `items` を schema と要求条件に従って返す。

エラーは `Status` オブジェクトで返す。

```json
{
  "apiVersion": "v1", "kind": "Status", "status": "Failure",
  "message": "...", "reason": "NotFound", "code": 404
}
```

`reason`、`details`、`causes`、`retryAfterSeconds` は kubectl とクライアントが
分岐に使うため、v1.36.2 の同一要求と一致させる。内部例外の class 名、backtrace、
host path、token および Secret 値を `message` に含めてはならない。

<a id="sec-4-4"></a>
## 4.4 watch

`?watch=true&resourceVersion=N` でストリームを開始する。JSON/YAML では各イベントを
独立したオブジェクトとして逐次 encode し、Protobuf では Kubernetes framing に従う。

```jsonl
{"type":"ADDED","object":{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web"}}}
{"type":"MODIFIED","object":{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web"}}}
{"type":"DELETED","object":{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web"}}}
{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"N"}}}
```

要件:

- W1: `resourceVersion=N` を指定した場合、N より後の変更のみを送る
- W2: N が古すぎて保持していない場合、`410 Gone` を返す。クライアントは再 list する
- W3: `allowWatchBookmarks=true` では、変更がなくても最大 30 秒間隔で BOOKMARK を送り、再開点を保持させる
- W4: 接続が切れてもサーバ側に状態を残さない
- W5: 同一開始 revision の複数 watcher は同じ変更を同じ revision 順で観測する
- W6: `sendInitialEvents=true` では初期状態を synthetic `ADDED` として送り、直後に初期同期完了 BOOKMARK を送る
- W7: 1 watcher の送信待ち buffer は 1,024 event または 16 MiB の小さい方を上限とし、超過時は接続を終了して再 list を要求する

<a id="sec-4-5"></a>
## 4.5 楽観的並行制御

- update strategy が resourceVersion を要求するリソースでは、空または不一致を `409 Conflict` とする
- unconditional update を許すかは GVR ごとの v1.36.2 strategy corpus に従い、全リソース共通の例外を設けない
- status サブリソースの更新は spec を変更せず、通常 endpoint の更新は status を変更しない
- Server-Side Apply は structured-merge-diff と同じ field set、manager、operation、time、conflict、force semantics を実装し、`metadata.managedFields` を保持する
- JSON Patch の `test`、Strategic Merge Patch の merge key / retainKeys、CRD の listType / mapType / structType を schema に従って処理する
- mutation、defaulting、validation、field management が完了した最終オブジェクトだけを 1 revision として commit する

<a id="sec-4-6"></a>
## 4.6 互換性判定

API 互換性は、Ruby 実装と隔離した Kubernetes v1.36.2 oracle に同一の初期状態と要求列を与え、
応答および watch trace を比較して判定する。比較器は動的値を意味に従って対応付けるが、
未知フィールド、default、field ownership、event type、HTTP status、`Status` の構造を無視してはならない。

upstream conformance test の skip、書換え、期待値変更は禁止する。Linux 以外、特定 cloud provider、
特定ハードウェアを要求する test の除外は、test ID、理由、対象外境界を機械可読な allowlist に記録する。
allowlist に API、Controller、Scheduler、Node、Network、Storage の Linux core behavior を加えてはならない。

## Related

- [api server](api-server.md)
- [schema compiler](../ruby/schema-compiler.md)
- [testing](../verification/testing.md)
