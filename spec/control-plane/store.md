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

内部の作成、更新、削除では、`related_versions`で別のキーの`resourceVersion`をコミットの条件にできる。値が`nil`のキーは未作成であることを確認する。条件の確認と書き込みは同じコミット内で行い、条件を満たさなければ`Conflict`を返す。

ServiceのNodePortにはポート番号をキーとする内部予約を作る。Serviceの書き込みは、取得したNodePortとClusterIPの予約が同じ`resourceVersion`で残っている場合に限りコミットする。使われていない予約の解放では、予約を参照するはずのServiceの`resourceVersion`も確認する。

スナップショットには、現在のオブジェクトと、保持期間内の読み取りに必要な版を保存する。削除のリビジョンが compaction の境界に達し、それより新しい版がなければ、そのキーの履歴を取り除く。同じ名前を再作成した場合は新しいリビジョンを割り当てる。

形式 v1 の省略可能な `resource_revisions` は、キー空間ごとの最終更新リビジョンを保存する。これにより、最後の操作が削除で履歴を整理した後も、再起動したレプリカで同じ更新番号を参照できる。このフィールドを持たない旧スナップショットの復元時は、保存されている版から更新番号を求める。

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

メモリと Raft の既定値は `datastore.history_retention_policy: longer_window`。24時間と100,000リビジョンをどちらも外れた、連続する先頭の履歴を整理する。`compatibility` を指定すると、5分か100,000リビジョンのどちらかを外れた履歴を整理する。

LIST の継続トークンは最初のページから5分で失効する。失効時は `410 Gone` を返し、`Status.metadata.continue` に最新スナップショットから同じキーの直後に再開できるトークンを入れる。WATCH と `resourceVersionMatch=Exact` の LIST は保持中のリビジョンを引き続き参照できる。設定方法は[運用手順](../../deploy/cluster/README.md#watch-history-retention)に記載する。

## 関連

- [Raft](raft.md)
- [APIサーバ](../api/api-server.md)
- [02 ストレージとRaft](../diagrams/02-storage-raft.md)
