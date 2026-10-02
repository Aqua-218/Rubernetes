[仕様書の目次](../README.md) / [制御面](README.md)

<a id="sec-5-3"></a>
# 5.3 Raft

> 対象読者: 分散システムの実装者、形式検証の担当者
>
> 状態: 規範、版0.2

Ruby製のRaftについて、タイミング、WAL、コミット、スナップショット、トランスポート、メンバーシップを定義する。

図は[図02 ストレージとRaft](../diagrams/02-storage-raft.md)にある。

OngaroとOusterhoutによるRaftの論文に従う。以下は、本実装で決めた事項である。

<a id="sec-5-3-1"></a>
## 5.3.1 パラメータ

| 項目 | 値 |
|---|---|
| election timeout | 150〜300 msの範囲からランダムに選ぶ |
| heartbeat interval | 50 ms |
| 1バッチの最大エントリ数 | 256 |
| 1バッチのエンコード後の最大サイズ | 1 MiB |
| バッチをflushするまでの時間 | 2 ms |
| スナップショットを取る契機 | コミット済みのエントリが100,000件に達するか、WALが512 MiBに達するか、どちらか早いほう |
| スナップショットの最小間隔 | 30秒 |

election timeoutは、heartbeat intervalの3倍以上とする。3倍を下回ると、不要な選挙が起き、安定していたリーダーが交代してしまう。

<a id="sec-5-3-2"></a>
## 5.3.2 永続化

次の3つは、投票への応答とログへの応答を返す前に、fsyncが完了していなければならない。

- `currentTerm`
- `votedFor`
- ログエントリ

この順序を守らないと、再起動後に同じtermで二重に投票することがありうる。Raftの安全性が直接失われる箇所であり、性能を理由に緩めてはならない。

<a id="sec-5-3-3"></a>
## 5.3.3 ログ

- インデックスは1から始める。論文に合わせるためである。
- 各エントリは`{term, index, command}`で構成する。
- コミット済みのエントリは変更しない。

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
