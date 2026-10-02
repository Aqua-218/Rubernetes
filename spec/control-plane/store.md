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

| 番号 | 要件 |
|---|---|
| S1 | `resourceVersion`はストア全体で単調に増加する。リソースの種別ごとではない |
| S2 | watchは、listで得た`resourceVersion`から続けて開始できる。その間にイベントは欠落しない |
| S3 | 同じキーへの並行した更新は直列化される |
| S4 | watchの履歴は、直近100,000リビジョンと24時間のうち長いほうを既定で保持する。それより古い分はcompactionする。保持していないリビジョンからの再開には`410 Gone`を返す |
| S5 | リクエストボディ、WALのエントリ、スナップショットはチェックサムを持つ。破損を検出したあとは、部分的に適用しない |
| S6 | 同じrequest UIDの再送は二重に適用しない。保存済みの結果を返すか、同じ結果に収束させる |

## Related

- [raft](raft.md)
- [api server](../api/api-server.md)
- [02 storage raft](../diagrams/02-storage-raft.md)
