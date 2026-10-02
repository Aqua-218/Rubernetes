[仕様書の目次](../README.md) / [構成図](README.md)

<a id="sec-a-3"></a>
# A.3 図 03 — 制御ループ

> **Audience:** Controller/Scheduler実装者
>
> **Status:** Normative — version 0.2

Informer、WorkQueue、built-in/custom controller、schedulerのevent flowを示す。

```mermaid
graph TB

WS["Watch Server / 詳細図 01"]

subgraph INF["◤ Informer 基盤 / 全コントローラ共有 ◢"]
    R1["<b>Reflector</b><br/>ListAndWatch<br/>初回 full list → 差分追従"]
    R2["<b>再接続制御</b><br/>指数バックオフ + jitter<br/>410 Gone → relist<br/>bookmark で再開点保持"]
    R3["<b>DeltaFIFO</b><br/>Added/Updated/Deleted/Replaced/Sync<br/>キー単位で圧縮<br/>順序保証"]
    R4["<b>Indexer / ThreadSafeStore</b><br/>ローカルキャッシュ<br/>namespace · label インデックス<br/>カスタム indexFunc"]
    R5["<b>SharedInformer</b><br/>1つの watch を多数が共有<br/>EventHandler 登録<br/>ResyncPeriod"]
    R6["<b>Lister</b><br/>キャッシュからの読み<br/>API を叩かない"]
    R7["<b>WorkQueue</b><br/>重複排除 · 遅延投入<br/>rate limiter<br/>指数バックオフ再投入<br/>処理中キーのロック"]
end

subgraph LE["◤ リーダー選出 ◢"]
    LE1["<b>Lease ベース</b><br/>コントローラの単一実行保証<br/>renew · 失効時の退避"]
end

subgraph CTRL["◤ Controllers / reconcile ◢"]

    subgraph CD["Deployment"]
        D1["<b>世代管理</b><br/>ReplicaSet を revision 毎に作成<br/>pod-template-hash"]
        D2["<b>RollingUpdate</b><br/>maxSurge / maxUnavailable<br/>段階的な入替"]
        D3["<b>Recreate 戦略</b>"]
        D4["<b>Progress 判定</b><br/>progressDeadlineSeconds<br/>条件 Condition 更新"]
        D5["<b>Rollback</b><br/>revisionHistoryLimit<br/>過去 RS への復帰"]
        D6["<b>Pause / Resume</b>"]
    end

    subgraph CR["ReplicaSet"]
        S1["<b>差分収束</b><br/>desired − actual を埋める"]
        S2["<b>ownerReference 付与</b>"]
        S3["<b>削除優先度</b><br/>未Ready → 新しい → 再起動多い順"]
        S4["<b>expectations</b><br/>作成/削除の未反映を見越す<br/>過剰作成の防止"]
        S5["<b>孤児の養子縁組</b><br/>selector 一致 Pod の回収"]
    end

    subgraph CN["Node"]
        N1["<b>heartbeat 監視</b><br/>Lease 更新の途絶検出"]
        N2["<b>NotReady 判定</b><br/>猶予時間 · condition 遷移"]
        N3["<b>Taint 付与</b><br/>unreachable · not-ready"]
        N4["<b>Pod 退避</b><br/>toleration 秒数の尊重<br/>退避レート制限"]
    end

    subgraph CE["Endpoint"]
        E1["<b>selector 評価</b><br/>Service ↔ Pod の紐付け"]
        E2["<b>readiness 反映</b><br/>Ready のみ出す<br/>terminating の扱い"]
        E3["<b>EndpointSlice 分割</b><br/>大規模時の分割配信"]
    end

    subgraph CG["GarbageCollector"]
        G1["<b>所有グラフ構築</b><br/>全リソースを watch<br/>ownerReference で辺を張る"]
        G2["<b>孤児検出</b><br/>親の消失を検知"]
        G3["<b>カスケード削除</b><br/>Foreground / Background / Orphan"]
        G4["<b>循環参照の検出</b>"]
    end

    subgraph CNS["Namespace"]
        M1["<b>削除フェーズ</b><br/>deletionTimestamp 設定"]
        M2["<b>全資源の列挙</b><br/>Discovery から型一覧を引く<br/>CRD も含む"]
        M3["<b>finalizer 除去待ち</b><br/>全消滅を確認して完了"]
    end

    subgraph CX["カスタム / CRD 由来"]
        X1["<b>動的 Informer</b><br/>CRD 登録に追従して watch 開始"]
        X2["<b>汎用 reconcile 枠</b><br/>ユーザ定義の収束ロジック"]
        X3["<b>status サブリソース更新</b><br/>observedGeneration"]
    end
end

subgraph SCH["◤ Scheduler ◢"]
    Q1["<b>SchedulingQueue</b><br/>activeQ / backoffQ / unschedulableQ<br/>優先度ヒープ<br/>flush 契機の管理"]
    F1["<b>PreFilter</b><br/>事前計算 · 早期棄却"]
    F2["<b>Filter</b><br/>NodeResourcesFit<br/>NodeAffinity · nodeSelector<br/>Taint / Toleration<br/>PodAffinity · AntiAffinity<br/>VolumeBinding · ポート衝突"]
    F3["<b>PostFilter</b><br/>全滅時に Preemption 起動"]
    O1["<b>PreScore</b>"]
    O2["<b>Score</b><br/>LeastAllocated / MostAllocated<br/>TopologySpread<br/>ImageLocality"]
    O3["<b>NormalizeScore</b><br/>重み付き合算"]
    V1["<b>Reserve</b><br/>資源の仮確保"]
    V2["<b>Permit</b><br/>待機 · gang scheduling 余地"]
    V3["<b>PreBind / Bind / PostBind</b><br/>nodeName 書込<br/>失敗時の Unreserve"]
    PR1["<b>Preemption</b><br/>犠牲 Pod の選定<br/>PDB の尊重<br/>nominatedNodeName"]
    CC["<b>キャッシュ</b><br/>ノード状態のスナップショット<br/>assume した Pod の反映<br/>期限切れ処理"]
end

WS -.-> R1 --> R3 --> R4 --> R5
R2 -.-> R1
R5 --> R6
R5 --> R7
LE1 -.-> CTRL
LE1 -.-> SCH

R7 --> D1
R7 --> S1
R7 --> N1
R7 --> E1
R7 --> G1
R7 --> M1
R7 --> X1
R7 --> Q1

D1 --> D2 --> D4
D1 --> D3
D5 -.-> D1
D6 -.-> D2
S4 -.-> S1 --> S2
S1 --> S3
S5 -.-> S1
N1 --> N2 --> N3 --> N4
E1 --> E2 --> E3
G1 --> G2 --> G3
G4 -.-> G1
M1 --> M2 --> M3
X1 --> X2 --> X3

Q1 --> F1 --> F2 --> O1 --> O2 --> O3 --> V1 --> V2 --> V3
F2 -->|"全ノード不適合"| F3 --> PR1 --> Q1
CC -.-> F2
CC -.-> V1

D2 -->|"書き戻し"| API["API Server"]
S1 -->|"Pod 作成 / 削除"| API
E3 -->|"書き戻し"| API
N4 -->|"退避"| API
G3 -->|"削除"| API
V3 -->|"bind"| API
X3 -->|"status"| API

classDef inf fill:#1d2431,stroke:#7f8da5,color:#e6ecf5
classDef le  fill:#16202a,stroke:#4b9fd6,color:#e6ecf5
classDef ct  fill:#251a12,stroke:#e0a029,color:#e6ecf5
classDef sc  fill:#22200f,stroke:#c9b02a,color:#e6ecf5
classDef api fill:#241320,stroke:#e0294b,color:#e6ecf5

class WS,R1,R2,R3,R4,R5,R6,R7 inf
class LE1 le
class D1,D2,D3,D4,D5,D6,S1,S2,S3,S4,S5,N1,N2,N3,N4,E1,E2,E3,G1,G2,G3,G4,M1,M2,M3,X1,X2,X3 ct
class Q1,F1,F2,F3,O1,O2,O3,V1,V2,V3,PR1,CC sc
class API api
```

## Related

- [informer](../control-plane/informer.md)
- [controllers](../control-plane/controllers.md)
- [scheduler](../control-plane/scheduler.md)
