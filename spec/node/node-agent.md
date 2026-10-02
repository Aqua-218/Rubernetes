[仕様書の目次](../README.md) / [ノード](README.md)

<a id="sec-5-7"></a>
# 5.7 ノードエージェント

> 対象読者: ノードエージェントの実装者、ランタイムの実装者
>
> 状態: 規範、版0.2

PodのSyncLoopと、起動、probe、再起動、終了、evictionの順序を定義する。

図は[図04 ノードエージェント](../diagrams/04-node-agent.md)にある。ボリュームの詳細は[図07 ストレージとボリューム](../diagrams/07-storage-volume.md)を参照する。

<a id="sec-5-7-1"></a>
## 5.7.1 SyncLoop

- 自ノード宛の Pod を watch する
- イベント駆動に加え、既定 1 分周期で全 Pod を再同期する
- Pod ごとに直列化された worker を持つ。同一 Pod の操作は並行しない

> Volume の詳細は [図 07 — Storage / Volume](../diagrams/07-storage-volume.md) を参照。

<a id="sec-5-7-2"></a>
## 5.7.2 Pod 起動手順

順序を変更してはならない。

1. 受け入れ判定（リソース、ノードの状態）
2. Volume の準備
3. サンドボックス作成（namespace 群または microVM、[§5.8](runtime.md#sec-5-8)）
4. ネットワーク接続（[§5.9](network.md#sec-5-9)）
5. init コンテナを順に実行し、各々の完了を待つ
6. 通常コンテナを起動
7. status 報告

いずれかで失敗した場合、そこまでに作った資源を逆順に解放する。

<a id="sec-5-7-3"></a>
## 5.7.3 Probe

| 種別 | 失敗時の動作 |
|---|---|
| startup | 成功するまで liveness / readiness を開始しない |
| liveness | コンテナを再起動する |
| readiness | Endpoints から外す。再起動はしない |

方式は `exec` / `httpGet` / `tcpSocket`。

<a id="sec-5-7-4"></a>
## 5.7.4 再起動制御

`restartPolicy` に従う。連続失敗時は指数バックオフし、
再起動待ちは 10 秒から開始して 2 倍し、上限 300 秒で `CrashLoopBackOff` とする。
コンテナが連続 10 分稼働した時点で backoff を 10 秒へリセットする。

<a id="sec-5-7-5"></a>
## 5.7.5 終了処理

1. Endpoints から外す
2. preStop フックを実行する
3. `SIGTERM` を送る
4. `gracePeriodSeconds` 待つ
5. 残っていれば `SIGKILL`
6. ネットワーク解放、サンドボックス破棄、Volume 解放

<a id="sec-5-7-6"></a>
## 5.7.6 Eviction

メモリまたはディスクが閾値を下回った場合、
優先度の低い Pod から退去させる。
退去は `SIGKILL` ではなく通常の終了処理を経る。

## Related

- [runtime](runtime.md)
- [network](network.md)
- [volume](volume.md)
- [04 node agent](../diagrams/04-node-agent.md)
