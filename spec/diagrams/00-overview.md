[仕様書の目次](../README.md) / [構成図](README.md)

<a id="sec-a-0"></a>
# A.0 図00 全景

> 対象読者: 全読者、アーキテクト
>
> 状態: 規範、版0.2

クライアントから低層のランタイム、検証の層までを含む、システム全体のコンポーネントの配置を示す。

```mermaid
graph TB

subgraph L0["◤ CLIENT ◢"]
    C1["rubectl / 自作CLI"]
    C2["kubectl / 本物"]
end

subgraph L1["◤ API SERVER ◢ → 詳細図 01"]
    A1["Front Proxy · 認証 · RBAC"]
    A2["Priority &amp; Fairness · RESTMapper"]
    A3["Admission チェーン · Strategy"]
    A4["Scheme / Codec / バージョン変換"]
    A5["Watch Server"]
    A6["CRD / 動的型登録 · OpenAPI 検証"]
    A7["Audit / 監査ログ"]
end

subgraph L2["◤ STORAGE + 合意 ◢ → 詳細図 02"]
    S1["Storage IF ◇差替可"]
    S2["MVCC · WatchCache"]
    S3["Raft ◆自作"]
    S4["WAL · Snapshot · Membership"]
end

subgraph L3["◤ 制御ループ ◢ → 詳細図 03"]
    K1["Informer / DeltaFIFO / Indexer"]
    K2["WorkQueue"]
    K3["v1.36.2 built-in Controllers 全体"]
    K4["Scheduler · Preemption"]
    K5["カスタムコントローラ / CRD"]
end

subgraph L4["◤ NODE AGENT ◢ → 詳細図 04"]
    N1["SyncLoop · PodWorker"]
    N2["Prober · 再起動制御 · Eviction"]
    N3["VolumeManager"]
    N4["StatusReporter"]
end

subgraph L5["◤ 内部境界 / 標準接続 ◢"]
    I1["Runtime IF / RuntimeClass"]
    I2["Network IF / Ruby Native"]
    I3["Storage IF / CSI 互換"]
end

subgraph L6["◤ LOW LAYER ── syscall 直叩き ◢"]
    R1["Native Runtime ◆Ruby<br/>→ 詳細図 05"]
    R2["自作ネットワーク ◆<br/>→ 詳細図 06"]
    R3["自作ストレージ ◆<br/>→ 詳細図 07"]
    R4["eBPF Proxy ◆<br/>→ 詳細図 06"]
    R5["MicroVM Runtime ◆Ruby制御<br/>Firecracker / jailer → 詳細図 05"]
end

subgraph L7["◤ 横断関心 ◢ → 詳細図 08"]
    V1["モデル検査 · 線形化可能性"]
    V2["障害注入 / Chaos"]
    V3["メトリクス · 分散トレース"]
end

C1 -->|"REST"| A1
C2 -->|"REST"| A1
A1 --> A2 --> A3 --> A5
A4 -.-> A3
A6 -.-> A4
A3 --> A7
A3 --> S1
A5 -.-> S2
S1 --> S2 --> S3 --> S4
A5 -.->|"watch stream"| K1
K1 --> K2 --> K3
K2 --> K4
K2 --> K5
K3 -->|"書き戻し"| A1
K4 -->|"bind"| A1
K5 -->|"書き戻し"| A1
A5 -.->|"自ノード宛"| N1
N1 --> N2
N1 --> N3
N1 --> N4 -->|"status"| A1
N1 --> I1 --> R1
I1 --> R5
N1 --> I2 --> R2
N3 --> I3 --> R3
N1 --> R4
S3 -.-> V1
L4 -.-> V2
L3 -.-> V3

classDef cl fill:#12202e,stroke:#4b9fd6,color:#e6ecf5
classDef ap fill:#241320,stroke:#e0294b,color:#e6ecf5
classDef st fill:#2a1a24,stroke:#ff5c78,color:#e6ecf5
classDef ct fill:#251a12,stroke:#e0a029,color:#e6ecf5
classDef ag fill:#241d10,stroke:#e0a029,color:#e6ecf5
classDef if fill:#16202a,stroke:#4b9fd6,color:#e6ecf5
classDef lo fill:#1b1630,stroke:#8b6ef0,color:#e6ecf5
classDef ve fill:#101c1a,stroke:#3fae8f,color:#e6ecf5

class C1,C2 cl
class A1,A2,A3,A4,A5,A6,A7 ap
class S1,S2,S3,S4 st
class K1,K2,K3,K4,K5 ct
class N1,N2,N3,N4 ag
class I1,I2,I3 if
class R1,R2,R3,R4,R5 lo
class V1,V2,V3 ve
```

## 関連

- [architecture](../foundation/architecture.md)
- [構成図インデックス](README.md)
