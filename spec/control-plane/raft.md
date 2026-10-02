[仕様書の目次](../README.md) / [制御面](README.md)

<a id="sec-5-3"></a>
# 5.3 Raft

> 対象読者: 分散システムの実装者、形式検証の担当者
>
> 状態: 規範、版0.2

Ruby製のRaftについて、タイミング、WAL、コミット、スナップショット、トランスポート、メンバーシップを定義する。


> **Diagram:** [図 02 — Storage / Raft](../diagrams/02-storage-raft.md)

Raft 論文（Ongaro & Ousterhout）に従う。以下は本実装の決定事項。

<a id="sec-5-3-1"></a>
## 5.3.1 パラメータ

| 項目 | 値 |
|---|---|
| election timeout | 150〜300 ms からランダム |
| heartbeat interval | 50 ms |
| 最大バッチ entry 数 | 256 entry |
| 最大バッチ encoded size | 1 MiB |
| バッチ flush timeout | 2 ms |
| スナップショット契機 | commit 済み 100,000 entry または WAL 512 MiB の先着 |
| スナップショット最小間隔 | 30 秒 |

election timeout は heartbeat interval の 3 倍以上とする。
これを下回ると安定したリーダーが不要な選挙で失われる。

<a id="sec-5-3-2"></a>
## 5.3.2 永続化

以下は投票応答・ログ応答を返す**前に** fsync 完了していなければならない。

- `currentTerm`
- `votedFor`
- ログエントリ

この順序が破れると、再起動後に同一 term で二重投票が起こりうる。
Raft の安全性が直接崩れる箇所であり、性能を理由に緩和してはならない。

<a id="sec-5-3-3"></a>
## 5.3.3 ログ

- 1-indexed とする（論文に合わせる）
- 各エントリは `{term, index, command}`
- コミット済みエントリは変更しない

<a id="sec-5-3-4"></a>
## 5.3.4 コミット規則

リーダーは、自分の現 term のエントリが過半数に複製された場合にのみ
`commitIndex` を進める。過去 term のエントリを複製数のみで
コミットしてはならない（論文 §5.4.2）。

<a id="sec-5-3-5"></a>
## 5.3.5 スナップショット

- 状態機械の全状態と、最後に含まれる `index` / `term` を記録する
- 遅延フォロワーには `InstallSnapshot` で転送する
- スナップショット済み範囲のログを切り詰める

<a id="sec-5-3-6"></a>
## 5.3.6 トランスポート

- 自作 RPC。フレーム形式は `[長さ 4 byte][種別 1 byte][ペイロード]`
- frame length は payload を確保する前に検査し、上限 16 MiB を超えた接続を切断する
- peer certificate の cluster ID と node ID を検証し、接続内容から caller identity を確定する
- 再送はアプリケーション層で行う。RPC は `{cluster_id,node_id,term,request_id}` で冪等化する
- リーダーからフォロワーへの `AppendEntries` はパイプライン化する

<a id="sec-5-3-7"></a>
## 5.3.7 メンバーシップ変更

joint consensus 方式を用いる。single-server change は用いない。
理由: 実装は単純だが、特定の順序で複数変更を行うと安全性が壊れる既知の問題がある。

## Related

- [store](store.md)
- [formal methods](../verification/formal-methods.md)
- [02 storage raft](../diagrams/02-storage-raft.md)
