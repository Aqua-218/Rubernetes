[仕様書の目次](../README.md) / [構成図](README.md)

<a id="sec-a-4"></a>
# A.4 図04 ノードエージェント

> 対象読者: ノードエージェントとランタイムの実装者
>
> **Status:** Normative — version 0.2

Pod workerからruntime、network、volume、statusへのlifecycle flowを示す。

```mermaid
graph TB

W["API Server watch / 自ノード宛"]

subgraph SRC["◤ Pod 供給源 ◢"]
    S1["<b>API 由来</b><br/>spec.nodeName == self"]
    S2["<b>static Pod</b><br/>マニフェストディレクトリ監視<br/>mirror Pod を API に作る"]
    S3["<b>統合チャネル</b><br/>複数ソースのマージ<br/>更新差分の生成"]
end

subgraph LOOP["◤ SyncLoop ◢"]
    L1["<b>イベント駆動</b><br/>Pod 追加/更新/削除<br/>ランタイム状態変化"]
    L2["<b>周期 resync</b><br/>取りこぼしの回収"]
    L3["<b>PodWorker</b><br/>Pod 単位で直列化<br/>並行 Pod 間は並列<br/>実行中の中断制御"]
    L4["<b>アクション決定</b><br/>desired ⇄ actual 差分<br/>作成 / 更新 / 削除 / 何もしない"]
end

subgraph ADMIT["◤ ノード側受け入れ判定 ◢"]
    A1["<b>資源の空き確認</b><br/>allocatable − 割当済"]
    A2["<b>OS / arch 適合</b>"]
    A3["<b>拒否時</b><br/>status=Failed reason=OutOfcpu<br/>再スケジュール誘発"]
end

subgraph CREATE["◤ Pod 起動手順 ◢"]
    C1["<b>Sandbox 作成</b><br/>Pod 用 netns · IPC · UTS<br/>pause 相当プロセス"]
    C2["<b>ネットワーク接続</b><br/>Network IF 呼出<br/>IP 割当 · 経路設定"]
    C3["<b>Volume 準備</b><br/>Storage IF 呼出<br/>マウント完了待ち"]
    C4["<b>initContainers</b><br/>順次実行 · 完了待ち<br/>失敗時の再試行"]
    C5["<b>通常コンテナ起動</b><br/>Runtime IF 呼出<br/>起動順序 · 依存"]
    C6["<b>sidecar / restartable init</b>"]
end

subgraph PROBE["◤ Probe と再起動 ◢"]
    P1["<b>startupProbe</b><br/>起動猶予の確保"]
    P2["<b>livenessProbe</b><br/>exec · httpGet · tcpSocket<br/>失敗閾値 → コンテナ再起動"]
    P3["<b>readinessProbe</b><br/>Endpoint への出し入れ"]
    P4["<b>再起動ポリシー</b><br/>Always / OnFailure / Never"]
    P5["<b>CrashLoopBackOff</b><br/>指数バックオフ<br/>上限と回数リセット"]
end

subgraph LIFE["◤ 終了処理 ◢"]
    T1["<b>preStop フック</b>"]
    T2["<b>SIGTERM 送出</b>"]
    T3["<b>terminationGracePeriod</b><br/>猶予後 SIGKILL"]
    T4["<b>後片付け</b><br/>netns 解放 · volume umount<br/>cgroup 削除 · rootfs 破棄"]
end

subgraph VOL["◤ VolumeManager ◢"]
    V1["<b>desired / actual 状態表</b>"]
    V2["<b>attach · mount 調停</b><br/>参照カウント"]
    V3["<b>emptyDir · hostPath</b>"]
    V4["<b>configMap · secret</b><br/>投影 · 更新反映"]
    V5["<b>CSI 相当 呼出</b><br/>→ 詳細図 07"]
end

subgraph RES["◤ 資源管理 ◢"]
    G1["<b>cgroup 階層</b><br/>QoS クラス毎<br/>Guaranteed / Burstable / BestEffort"]
    G2["<b>Node Allocatable</b><br/>system 予約 · kube 予約"]
    G3["<b>統計収集</b><br/>cgroup から cpu/mem/io 読出<br/>コンテナ毎 · Pod 毎"]
end

subgraph EVICT["◤ Eviction ◢"]
    E1["<b>閾値監視</b><br/>memory.available<br/>nodefs.available · inodesFree"]
    E2["<b>soft / hard 閾値</b><br/>猶予期間の扱い"]
    E3["<b>退去順序</b><br/>QoS → 超過量 → 優先度"]
    E4["<b>ノード condition 反映</b><br/>MemoryPressure · DiskPressure<br/>Taint 経由でスケジュール抑止"]
end

subgraph GC["◤ GC ◢"]
    B1["<b>コンテナ GC</b><br/>終了済みの保持数上限"]
    B2["<b>イメージ GC</b><br/>ディスク使用率閾値<br/>最終使用時刻順に削除"]
end

subgraph STAT["◤ 状態報告 ◢"]
    R1["<b>PodStatus 集約</b><br/>phase 算出<br/>containerStatuses<br/>Ready 条件"]
    R2["<b>Node status</b><br/>capacity · allocatable<br/>conditions · イメージ一覧"]
    R3["<b>Node Lease</b><br/>軽量 heartbeat"]
    R4["<b>Event 発行</b><br/>Pulling · Started · Killing<br/>重複集約"]
end

subgraph SUB["◤ サブリソース ◢"]
    U1["<b>logs</b><br/>ストリーム · follow · tail"]
    U2["<b>exec / attach</b><br/>pty · stdin 双方向<br/>ストリーム多重化"]
    U3["<b>port-forward</b>"]
end

W --> S1 --> S3
S2 --> S3
S3 --> L1 --> L3
L2 -.-> L3
L3 --> L4 --> A1 --> A2
A2 -->|"不可"| A3
A2 -->|"可"| C1 --> C2
C1 --> C3
C2 --> C4
C3 --> C4
C4 --> C5
C6 -.-> C5
C5 --> P1 --> P2
C5 --> P3
P2 --> P4 --> P5 --> L3
P3 -.->|"status"| R1
V1 --> V2 --> V3
V2 --> V4
V2 --> V5
C3 -.-> V1
G2 --> G1 --> G3
C5 -.-> G1
G3 --> E1 --> E2 --> E3 --> T1
E3 --> E4
G3 -.-> R2
L4 -->|"削除時"| T1 --> T2 --> T3 --> T4
T4 -.-> B1
B2 -.-> E1
C5 --> R1 --> R4
R1 -->|"status 報告"| API["API Server"]
R2 --> API
R3 --> API
R4 --> API
U1 -.-> C5
U2 -.-> C5
U3 -.-> C2

CRI["Runtime IF → 詳細図 05"]
CNI["Network IF → 詳細図 06"]
CSI["Storage IF → 詳細図 07"]
C5 --> CRI
C1 --> CRI
C2 --> CNI
V5 --> CSI

classDef src fill:#16202a,stroke:#4b9fd6,color:#e6ecf5
classDef lp  fill:#241d10,stroke:#e0a029,color:#e6ecf5
classDef cr  fill:#251a12,stroke:#e0a029,color:#e6ecf5
classDef pb  fill:#22200f,stroke:#c9b02a,color:#e6ecf5
classDef lf  fill:#2a1a24,stroke:#ff5c78,color:#e6ecf5
classDef vl  fill:#1d2431,stroke:#7f8da5,color:#e6ecf5
classDef rs  fill:#1b1630,stroke:#8b6ef0,color:#e6ecf5
classDef st  fill:#12202e,stroke:#4b9fd6,color:#e6ecf5
classDef api fill:#241320,stroke:#e0294b,color:#e6ecf5

class W,S1,S2,S3 src
class L1,L2,L3,L4,A1,A2,A3 lp
class C1,C2,C3,C4,C5,C6 cr
class P1,P2,P3,P4,P5 pb
class T1,T2,T3,T4 lf
class V1,V2,V3,V4,V5 vl
class G1,G2,G3,E1,E2,E3,E4,B1,B2 rs
class R1,R2,R3,R4,U1,U2,U3 st
class API,CRI,CNI,CSI api
```

## Related

- [node agent](../node/node-agent.md)
- [runtime](../node/runtime.md)
- [構成図インデックス](README.md)
