[仕様書の目次](../README.md) / [構成図](README.md)

<a id="sec-a-2"></a>
# A.2 図 02 — Storage / Raft

> **Audience:** Store/Raft実装者、形式検証者
>
> **Status:** Normative — version 0.2

MVCC、watch、WAL、Raft、snapshot、failure pathを示す。

```mermaid
graph TB

IN["API Server / Strategy 層から"]

subgraph SIF["◤ Storage Interface ◇差替可 ◢"]
    I1["<b>操作</b><br/>get · list · create<br/>guaranteedUpdate · delete<br/>watch · count"]
    I2["<b>guaranteedUpdate</b><br/>読み → 変換 → CAS<br/>競合時リトライループ"]
    I3["<b>Preconditions</b><br/>UID 一致 · resourceVersion 一致"]
    I4["<b>キー設計</b><br/>/registry/{resource}/{ns}/{name}<br/>プレフィックス列挙"]
end

subgraph MV["◤ MVCC / リビジョン ◢"]
    M1["<b>グローバル revision</b><br/>単調増加カウンタ<br/>resourceVersion として露出"]
    M2["<b>キー毎の版</b><br/>createRevision · modRevision<br/>version カウント"]
    M3["<b>楽観的並行制御</b><br/>compare-and-swap<br/>競合検出 → 409"]
    M4["<b>compaction</b><br/>古い版の回収<br/>compact revision 管理<br/>410 Gone の境界"]
    M5["<b>range 読み</b><br/>指定 revision でのスナップショット読み"]
end

subgraph WC["◤ Watch Cache ◢"]
    C1["<b>リングバッファ</b><br/>直近 N 件のイベント保持<br/>revision 範囲の管理"]
    C2["<b>list from cache</b><br/>ストアを叩かず応答<br/>整合性レベルの選択"]
    C3["<b>Broadcaster</b><br/>多数の watcher へ配信<br/>遅い watcher の切断"]
    C4["<b>初期同期</b><br/>full list → 差分追従<br/>cache 未追従時の待機"]
end

subgraph BK["◤ バックエンド ◢"]
    B1["<b>MemoryStore</b><br/>開発 · 単体テスト用<br/>同一 IF を満たす"]
    B2["<b>RaftStore</b><br/>本番経路<br/>読みは leader lease or read-index"]
end

subgraph RAFT["◤ RAFT ◆自作 ◢"]

    subgraph RROLE["役割と選挙"]
        E1["<b>Role 状態機械</b><br/>Follower ⇄ Candidate ⇄ Leader"]
        E2["<b>Election</b><br/>timeout ランダム化<br/>RequestVote<br/>過半数獲得判定"]
        E3["<b>Term 管理</b><br/>単調増加 · 降格条件<br/>古い term の拒否"]
        E4["<b>PreVote</b><br/>分断復帰時の term 汚染防止"]
        E5["<b>Leader Lease</b><br/>読みの線形化保証<br/>clock drift の考慮"]
    end

    subgraph RLOG["ログ"]
        G1["<b>Log 構造</b><br/>index · term · command<br/>append · truncate"]
        G2["<b>一致性検査</b><br/>prevLogIndex / prevLogTerm<br/>不一致時の巻き戻し探索"]
        G3["<b>Commit 前進</b><br/>matchIndex の中央値<br/>現 term のエントリのみ commit"]
        G4["<b>nextIndex / matchIndex</b><br/>フォロワー毎の追従状態"]
    end

    subgraph RREP["複製"]
        P1["<b>AppendEntries</b><br/>バッチ送信 · パイプライン<br/>heartbeat 兼用"]
        P2["<b>フロー制御</b><br/>inflight 上限<br/>遅延フォロワーの検出"]
        P3["<b>ReadIndex</b><br/>読み専用要求の線形化"]
    end

    subgraph RSNAP["スナップショット"]
        N1["<b>スナップショット生成</b><br/>状態機械の全体像<br/>lastIncluded index/term"]
        N2["<b>ログ圧縮</b><br/>閾値超過で truncate"]
        N3["<b>InstallSnapshot</b><br/>大幅遅延フォロワーへ転送<br/>チャンク分割"]
    end

    subgraph RMEM["メンバーシップ"]
        B_1["<b>joint consensus</b><br/>C_old,new の中間構成<br/>二重過半数"]
        B_2["<b>ノード追加</b><br/>learner 段階 · 追従待ち"]
        B_3["<b>ノード削除</b><br/>leader 自身の除去手順"]
    end

    subgraph RPERS["永続化"]
        S_1["<b>WAL</b><br/>追記専用 · セグメント分割<br/>CRC 検査"]
        S_2["<b>fsync 制御</b><br/>バッチ commit<br/>耐久性とスループットの調停"]
        S_3["<b>HardState</b><br/>term · votedFor · commit<br/>再起動時の復元"]
        S_4["<b>クラッシュ復帰</b><br/>WAL 再生 → snapshot 適用<br/>破損セグメントの切詰"]
    end

    subgraph RSM["状態機械"]
        F_1["<b>適用ループ</b><br/>commitIndex → appliedIndex<br/>順序保証"]
        F_2["<b>KV への確定適用</b><br/>put · delete · txn"]
        F_3["<b>べき等性</b><br/>クライアント要求ID<br/>重複適用の抑止"]
        F_4["<b>適用結果の通知</b><br/>待機中リクエストの解放"]
    end

    subgraph RTR["トランスポート"]
        T_1["<b>自作 RPC</b><br/>フレーム形式 · 多重化"]
        T_2["<b>再送 · タイムアウト</b>"]
        T_3["<b>ピア管理</b><br/>接続維持 · 再接続"]
    end
end

IN --> I1 --> I2 --> I3
I4 -.-> I1
I2 --> M3
M1 --> M2 --> M3 --> M4
M5 -.-> M1
M3 --> C1 --> C2
C1 --> C3
C4 -.-> C1
C3 -.->|"watch 配信"| OUTW["Watch Server へ"]
C2 --> B1
C2 --> B2

B2 --> E1
E1 --> E2 --> E3
E4 -.-> E2
E5 -.-> P3
E1 --> G1 --> G2 --> G3
G4 -.-> G3
G1 --> P1 --> P2
P3 -.-> G3
P1 --> T_1 --> T_2
T_3 -.-> T_1
G1 --> N1 --> N2
N1 --> N3 --> T_1
E1 --> B_1 --> B_2
B_1 --> B_3
G1 --> S_1 --> S_2
S_3 -.-> E3
S_4 -.-> S_1
N1 -.-> S_4
G3 --> F_1 --> F_2 --> F_4
F_3 -.-> F_1
F_2 -->|"確定値"| C1

VER["→ 検証層 詳細図 08<br/>モデル検査 · 線形化可能性"]
E1 -.-> VER
F_2 -.-> VER

classDef sif fill:#16202a,stroke:#4b9fd6,color:#e6ecf5
classDef mv  fill:#1d2431,stroke:#7f8da5,color:#e6ecf5
classDef wc  fill:#12202e,stroke:#4b9fd6,color:#e6ecf5
classDef bk  fill:#2a1a24,stroke:#ff5c78,color:#e6ecf5
classDef rf  fill:#241320,stroke:#e0294b,color:#e6ecf5
classDef ps  fill:#301620,stroke:#ff5c78,color:#e6ecf5
classDef ve  fill:#101c1a,stroke:#3fae8f,color:#e6ecf5

class IN,I1,I2,I3,I4 sif
class M1,M2,M3,M4,M5 mv
class C1,C2,C3,C4,OUTW wc
class B1,B2 bk
class E1,E2,E3,E4,E5,G1,G2,G3,G4,P1,P2,P3,N1,N2,N3,B_1,B_2,B_3,F_1,F_2,F_3,F_4,T_1,T_2,T_3 rf
class S_1,S_2,S_3,S_4 ps
class VER ve
```

## Related

- [store](../control-plane/store.md)
- [raft](../control-plane/raft.md)
- [構成図インデックス](README.md)
