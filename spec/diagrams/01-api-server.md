[仕様書の目次](../README.md) / [構成図](README.md)

<a id="sec-a-1"></a>
# A.1 図01 APIサーバ

> 対象読者: APIサーバの実装者
>
> 状態: 規範、版0.2

APIリクエストの処理経路と、admission、スキーム、ストレージとの接続を示す。

```mermaid
graph TB

REQ["リクエスト到着"]

subgraph FRONT["◤ フロント段 ◢"]
    F1["<b>TLS 終端</b><br/>x509 検証 · SNI<br/>HTTP/1.1 keepalive<br/>リクエストID 付与"]
    F2["<b>Panic Recovery</b><br/>タイムアウト制御<br/>最大ボディサイズ"]
end

subgraph AUTH["◤ 認証・認可 ◢"]
    AN1["<b>Authenticator チェーン</b>"]
    AN2["x509 クライアント証明書<br/>CN → user · O → group"]
    AN3["Bearer Token<br/>ServiceAccount JWT<br/>署名検証 · 有効期限"]
    AN4["匿名アクセス判定"]
    AZ1["<b>RBAC 評価器</b>"]
    AZ2["Role / RoleBinding<br/>namespace スコープ"]
    AZ3["ClusterRole / ClusterRoleBinding<br/>集約ルール aggregationRule"]
    AZ4["verb × resource × subresource<br/>ワイルドカード展開<br/>評価キャッシュ"]
end

subgraph FLOW["◤ 流量制御 ◢"]
    P1["<b>Priority &amp; Fairness</b>"]
    P2["FlowSchema マッチング<br/>subject · resource ルール"]
    P3["PriorityLevel キュー<br/>shuffle sharding<br/>公平配分 / fair queuing"]
    P4["並行度制限<br/>過負荷時 429 shedding"]
end

subgraph ROUTE["◤ ルーティング ◢"]
    M1["<b>RESTMapper</b><br/>GVK ↔ GVR 双方向解決<br/>単数/複数形 · 短縮名"]
    M2["パス解析<br/>/api/v1/namespaces/{ns}/{res}/{name}<br/>/apis/{grp}/{ver}/...<br/>subresource: /status /scale /logs /exec"]
    M3["<b>Discovery エンドポイント</b><br/>/apis 一覧 · APIResourceList<br/>kubectl の型解決に必須"]
end

subgraph SCHEME["◤ Scheme / Codec ◢"]
    SC1["<b>型レジストリ</b><br/>GVK → Ruby クラス登録<br/>内部型 / 外部型の分離"]
    SC2["<b>Codec</b><br/>YAML · JSON ↔ オブジェクト<br/>unknown フィールド保持<br/>strict / non-strict"]
    SC3["<b>バージョン変換</b><br/>v1alpha1 ⇄ v1beta1 ⇄ v1<br/>hub-spoke 変換<br/>ラウンドトリップ検証"]
    SC4["<b>Defaulting</b><br/>型ごとのデフォルト適用<br/>ゼロ値と未指定の区別"]
    SC5["<b>DeepCopy</b><br/>型ごとに生成<br/>キャッシュ汚染防止"]
end

subgraph CRD["◤ CRD / 拡張 ◢"]
    D1["<b>CustomResourceDefinition</b><br/>登録 · 削除 · finalizer"]
    D2["<b>動的型登録</b><br/>実行時に Scheme へ注入<br/>Discovery へ反映"]
    D3["<b>OpenAPI v3 スキーマ検証</b><br/>型 · 必須 · enum · pattern<br/>x-kubernetes-* 拡張"]
    D4["<b>structural schema</b><br/>pruning · preserveUnknownFields"]
    D5["<b>Conversion Webhook</b><br/>複数バージョン CRD の変換"]
    D6["<b>Subresource</b><br/>status / scale の分離"]
end

subgraph ADM["◤ Admission ◢"]
    AM1["<b>Mutating 段</b><br/>ServiceAccount 注入<br/>デフォルト値補完<br/>sidecar 注入 hook"]
    AM2["<b>Validating 段</b><br/>スキーマ検証<br/>フィールド間の相互制約<br/>immutable フィールド保護"]
    AM3["<b>ResourceQuota</b><br/>namespace 単位の総量<br/>予約と確定の二段"]
    AM4["<b>LimitRange</b><br/>下限 · 上限 · デフォルト"]
    AM5["<b>Webhook 呼出</b><br/>外部プラグイン<br/>failurePolicy · タイムアウト"]
end

subgraph STRAT["◤ Strategy / 永続化 ◢"]
    T1["<b>PrepareForCreate</b><br/>status クリア · UID 採番<br/>creationTimestamp"]
    T2["<b>PrepareForUpdate</b><br/>immutable 差戻し<br/>generation インクリメント"]
    T3["<b>ValidateUpdate</b><br/>遷移の妥当性"]
    T4["<b>DryRun</b><br/>永続化せず結果だけ返す"]
    T5["<b>Finalizer 処理</b><br/>deletionTimestamp 設定<br/>全 finalizer 除去まで残す"]
    T6["<b>ServerSideApply</b><br/>managedFields 追跡<br/>フィールド所有権 · 競合検出"]
end

subgraph WATCH["◤ Watch 配信 ◢"]
    W1["<b>Watch Server</b><br/>chunked transfer<br/>長時間接続の維持"]
    W2["<b>resourceVersion 起点</b><br/>途中再開 · 410 Gone 判定"]
    W3["<b>bookmark イベント</b><br/>進捗通知でrelist削減"]
    W4["<b>フィルタ</b><br/>label · field selector<br/>namespace 絞り"]
end

subgraph AUD["◤ 監査 ◢"]
    U1["<b>Audit Policy</b><br/>None/Metadata/Request/RequestResponse<br/>ルールマッチング"]
    U2["<b>ステージ記録</b><br/>RequestReceived<br/>ResponseStarted<br/>ResponseComplete · Panic"]
    U3["<b>Backend</b><br/>構造化ログ出力<br/>バッファ · バッチ書出"]
end

REQ --> F1 --> F2 --> AN1
AN1 --> AN2 --> AZ1
AN1 --> AN3 --> AZ1
AN1 --> AN4 --> AZ1
AZ1 --> AZ2 --> AZ4
AZ1 --> AZ3 --> AZ4
AZ4 --> P1 --> P2 --> P3 --> P4
P4 --> M1 --> M2
M1 -.-> M3
SC1 -.-> M1
M2 --> AM1 --> AM2 --> AM3 --> AM4
AM2 -.-> AM5
D1 --> D2 --> SC1
D2 -.-> M3
D3 -.-> AM2
D4 -.-> D3
D5 -.-> SC3
AM4 --> T1
AM4 --> T2 --> T3
T3 --> T6
T1 --> T6
T6 --> T4
T6 --> T5
T6 -->|"Storage IF へ"| OUT["Storage 層 → 詳細図 02"]
SC2 -.-> T6
SC4 -.-> AM1
SC5 -.-> T6
SC3 -.-> SC2
OUT -.-> W1 --> W2 --> W3
W4 -.-> W1
F2 -.-> U1 --> U2 --> U3
T6 -.-> U2

classDef fr fill:#16202a,stroke:#4b9fd6,color:#e6ecf5
classDef au fill:#241320,stroke:#e0294b,color:#e6ecf5
classDef fl fill:#2a1a24,stroke:#ff5c78,color:#e6ecf5
classDef ro fill:#251a12,stroke:#e0a029,color:#e6ecf5
classDef sc fill:#1d2431,stroke:#7f8da5,color:#e6ecf5
classDef cd fill:#1b1630,stroke:#8b6ef0,color:#e6ecf5
classDef ad fill:#22200f,stroke:#c9b02a,color:#e6ecf5
classDef st fill:#241d10,stroke:#e0a029,color:#e6ecf5
classDef wa fill:#12202e,stroke:#4b9fd6,color:#e6ecf5
classDef ud fill:#101c1a,stroke:#3fae8f,color:#e6ecf5

class REQ,F1,F2 fr
class AN1,AN2,AN3,AN4,AZ1,AZ2,AZ3,AZ4 au
class P1,P2,P3,P4 fl
class M1,M2,M3 ro
class SC1,SC2,SC3,SC4,SC5 sc
class D1,D2,D3,D4,D5,D6 cd
class AM1,AM2,AM3,AM4,AM5 ad
class T1,T2,T3,T4,T5,T6,OUT st
class W1,W2,W3,W4 wa
class U1,U2,U3 ud
```

## 関連

- [api server](../api/api-server.md)
- [kubernetes api](../api/kubernetes-api.md)
- [構成図インデックス](README.md)
