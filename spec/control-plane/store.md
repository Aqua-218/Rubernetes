[仕様書インデックス](../README.md) / [control-plane](README.md)

<a id="sec-5-2"></a>
# 5.2 Store

> **Audience:** Store実装者、分散システム検証者
>
> **Status:** Normative — version 0.2

MVCC Store の操作、revision、watch履歴、競合処理、破損検出を定義する。


> **Diagram:** [図 02 — Storage / Raft](../diagrams/02-storage-raft.md)

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

`guaranteed_update` はブロックを受け、競合時に最大 8 回再実行する。
待機は 5 ms から始めて 2 倍し、最大 640 ms の full jitter とする。
8 回競合した場合は `Conflict` を返し、呼び出し元が新しい要求として再試行する。

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
