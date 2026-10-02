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
| `compat/kubernetes/v1.36.2/discovery/` | group、version、resource、scope、verb、shortName、category、subresource | upstream 応答を正規化して固定 |
| `compat/kubernetes/v1.36.2/openapi/` | field、型、required、default、validation、patch strategy | upstream 配布物の SHA-256 を固定 |
| `compat/kubernetes/v1.36.2/protobuf/` | wire field number と message 定義 | upstream `.proto` と descriptor set を固定 |
| `compat/kubernetes/v1.36.2/conformance.yaml` | 規範的な API と E2E 挙動 | upstream test list を無変更で固定 |
| `compat/kubernetes/v1.36.2/features.yaml` | feature gate、既定値、対象 API | 全 gate の on/off profile を生成 |

CRD を登録した場合は、その served version、subresource、conversion、defaulting、CEL validation、
selectable field、printer column、OpenAPI 公開および discovery 反映を built-in resource と同じ経路で扱う。
API corpus に新しい GVK を追加すると、[§6.2](../ruby/schema-compiler.md#sec-6-2) の生成処理により型、codec、validation、DSL、RBS、
OpenAPI および差分計算が同時に生成されなければならない。

<a id="sec-4-2"></a>
## 4.2 エンドポイント

core group は `/api/{version}`、named group は `/apis/{group}/{version}` を基点とする。
各 GVR の scope と verbs は discovery corpus に従い、次のテンプレートから機械生成する。

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

Namespaced resource の `{base}` は
`.../namespaces/{namespace}`、全 namespace の list/watch は group/version 直下とする。

PATCH は次をすべて実装する。

| Content-Type | 意味 |
|---|---|
| `application/json-patch+json` | RFC 6902 JSON Patch |
| `application/merge-patch+json` | RFC 7386 JSON Merge Patch |
| `application/strategic-merge-patch+json` | schema の patch strategy を使う Strategic Merge Patch |
| `application/apply-patch+yaml` | Server-Side Apply |
| `application/apply-patch+cbor` | CBOR apply。対応 feature gate 無効時は upstream と同じ拒否 |

list、watch、deletecollection は `labelSelector`、`fieldSelector`、`limit`、`continue`、
`resourceVersion`、`resourceVersionMatch`、`timeoutSeconds`、`allowWatchBookmarks`、
`sendInitialEvents` を v1.36.2 と同じ validation および意味で処理する。

補助エンドポイント:

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

`exec`、`attach`、`portforward`、`log`、`proxy`、`eviction`、`binding`、`scale`、
`status`、`token`、`approval` 等の subresource は discovery corpus の verb と
Kubernetes streaming protocol に従う。HTTP/1.1、HTTP/2、WebSocket、SPDY fallback、
JSON、YAML、Kubernetes Protobuf、gzip を content negotiation で選択する。

`kubectl` は起動時に discovery 系（`/api`、`/apis`、`APIResourceList`）を
必ず叩く。ここが正しく返らないと以降が一切動かない。実装順で最優先とする。

<a id="sec-4-3"></a>
## 4.3 レスポンス形式

すべてのリソースは `apiVersion`、`kind` および schema が指定する metadata を持つ。
`spec` と `status` は当該 GVK の schema に存在する場合だけ持つ。次は Pod の例である。

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
