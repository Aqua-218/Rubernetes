[仕様書の目次](../README.md) / [制御面](README.md)

<a id="sec-5-2"></a>
# 5.2 ストア

> 対象読者: ストアの実装者、分散システムの検証者
>
> 状態: 規範、版0.2

MVCCストアの操作、リビジョン、watchの履歴、競合の処理、破損の検出を定義する。

図は[図02 ストレージとRaft](../diagrams/02-storage-raft.md)にある。

<a id="sec-5-2-1"></a>
## 5.2.1 インターフェース

```text
get(key, out:)                   → object | NotFound
list(prefix, selector:)          → [objects], resourceVersion
create(key, object)              → object | AlreadyExists
guaranteed_update(key, prec:) {} → object | Conflict
delete(key, prec:)               → object | NotFound | Conflict
watch(prefix, since:)            → イベントストリーム
```

`guaranteed_update`はブロックを受け取る。競合が起きたときは、ブロックを最大8回まで再実行する。待ち時間は5 msから始めて2倍ずつ増やし、最大640 msとする。待ち時間にはfull jitterを適用する。

8回続けて競合した場合は`Conflict`を返す。呼び出し元は、新しい要求としてやり直す。

<a id="sec-5-2-2"></a>
## 5.2.2 要件

- S1: `resourceVersion` はストア全体で単調増加する。リソース種別ごとではない
- S2: watch は list で得た `resourceVersion` から継続でき、イベントの欠落がない
- S3: 同一キーへの並行更新は直列化される
- S4: watch 履歴は既定で直近 100,000 revision か 24 時間の長い方を保持する。超過分は compaction し、それより古い再開は `410 Gone`
- S5: request body、WAL entry、snapshot は checksum を持ち、破損検出後に部分適用しない
- S6: 同一 request UID の再送は、保存済み結果を返すか同一結果へ収束し、二重適用しない

## Related

- [raft](raft.md)
- [api server](../api/api-server.md)
- [02 storage raft](../diagrams/02-storage-raft.md)
