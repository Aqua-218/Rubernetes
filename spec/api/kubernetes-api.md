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

### list

listは、対応するList kind、`metadata.resourceVersion`、`continue`、`remainingItemCount`、`items`を返す。内容はスキーマと要求の条件に従う。

### エラー

エラーは`Status`オブジェクトで返す。

```json
{
  "apiVersion": "v1", "kind": "Status", "status": "Failure",
  "message": "...", "reason": "NotFound", "code": 404
}
```

`reason`、`details`、`causes`、`retryAfterSeconds`は、v1.36.2が同じ要求に返す値と一致させる。kubectlやクライアントが、これらの値で処理を分岐するためである。

`message`に次のものを含めてはならない。

- 内部の例外のクラス名
- バックトレース
- ホスト上のパス
- トークン
- Secretの値

<a id="sec-4-4"></a>
## 4.4 watch

`?watch=true&resourceVersion=N`でストリームを開始する。JSONとYAMLでは、各イベントを独立したオブジェクトとして順にエンコードする。ProtobufではKubernetesのフレーミングに従う。

```jsonl
{"type":"ADDED","object":{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web"}}}
{"type":"MODIFIED","object":{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web"}}}
{"type":"DELETED","object":{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web"}}}
{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"N"}}}
```

watchの要件は次のとおりである。

| 番号 | 要件 |
|---|---|
| W1 | `resourceVersion=N`を指定した場合、Nより後の変更だけを送る |
| W2 | Nが古く、サーバがその履歴を保持していない場合は`410 Gone`を返す。クライアントはlistをやり直す |
| W3 | `allowWatchBookmarks=true`の場合、変更がなくても最大30秒の間隔でBOOKMARKを送り、クライアントに再開点を持たせる |
| W4 | 接続が切れても、サーバ側に状態を残さない |
| W5 | 同じリビジョンから始めた複数のwatcherは、同じ変更を同じリビジョン順で観測する |
| W6 | `sendInitialEvents=true`の場合、初期状態を合成した`ADDED`として送る。その直後に、初期同期の完了を示すBOOKMARKを送る |
| W7 | 1つのwatcherの送信待ちバッファは、1,024イベントと16 MiBのうち小さいほうを上限とする。上限を超えたら接続を終了し、listのやり直しを要求する |

<a id="sec-4-5"></a>
## 4.5 楽観的並行制御

- update strategyがresourceVersionを要求するリソースでは、resourceVersionが空の場合と一致しない場合に`409 Conflict`を返す。
- 無条件の更新を許すかどうかは、GVRごとにv1.36.2のstrategyコーパスに従う。全リソース共通の例外は設けない。
- statusサブリソースの更新はspecを変更しない。通常のエンドポイントの更新はstatusを変更しない。
- Server-Side Applyは、structured-merge-diffと同じ意味論を実装する。対象はfield set、manager、operation、time、conflict、forceである。`metadata.managedFields`を保持する。
- JSON Patchの`test`、Strategic Merge Patchのmerge keyと`retainKeys`、CRDのlistType、mapType、structTypeを、スキーマに従って処理する。
- mutation、defaulting、validation、フィールド管理がすべて終わった最終のオブジェクトだけを、1つのリビジョンとしてコミットする。

<a id="sec-4-6"></a>
## 4.6 互換性判定

### 判定の方法

APIの互換性は、Ruby実装と、隔離したKubernetes v1.36.2に、同じ初期状態と同じ要求の列を与えて判定する。両者の応答とwatchのトレースを比較する。

比較器は、動的な値を意味に従って対応付ける。ただし、次のものを無視してはならない。

- 未知のフィールド
- 既定値
- フィールドの所有権
- イベントの種別
- HTTPステータス
- `Status`の構造

### upstreamのテストの扱い

upstreamのconformanceテストについて、スキップ、書き換え、期待値の変更は禁止する。

Linux以外の環境、特定のクラウドプロバイダ、特定のハードウェアを必要とするテストは除外できる。除外するときは、テストID、理由、対象外とする境界を、機械可読な許可リストに記録する。

API、コントローラ、スケジューラ、ノード、ネットワーク、ストレージについて、Linuxでの中核となる挙動を許可リストに加えてはならない。

## Related

- [api server](api-server.md)
- [schema compiler](../ruby/schema-compiler.md)
- [testing](../verification/testing.md)
