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

- 自分のノードに割り当てられたPodをwatchする。
- イベントで動くのに加えて、既定で1分ごとにすべてのPodを再同期する。
- Podごとに、直列化されたworkerを持つ。同じPodへの操作が並行して走ることはない。

<a id="sec-5-7-2"></a>
## 5.7.2 Podの起動手順

次の順序を変更してはならない。

1. 受け入れの判定。リソースとノードの状態を確認する。
2. ボリュームの準備。
3. サンドボックスの作成。namespace群またはmicroVMを作る。[5.8](runtime.md#sec-5-8)を参照。
4. ネットワークへの接続。[5.9](network.md#sec-5-9)を参照。
5. initコンテナの実行。順に実行し、1つずつ完了を待つ。
6. 通常のコンテナの起動。
7. statusの報告。

いずれかの段階で失敗した場合は、そこまでに作った資源を逆の順に解放する。

<a id="sec-5-7-3"></a>
## 5.7.3 probe

| 種別 | 失敗したときの動作 |
|---|---|
| startup | 成功するまでlivenessとreadinessを始めない |
| liveness | コンテナを再起動する |
| readiness | Endpointsから外す。再起動はしない |

probeの方式は`exec`、`httpGet`、`tcpSocket`の3つである。

<a id="sec-5-7-4"></a>
## 5.7.4 再起動制御

`restartPolicy`に従う。連続して失敗した場合は、指数バックオフで待つ。

- 再起動までの待ち時間は10秒から始め、2倍ずつ増やす。
- 上限は300秒とし、その状態を`CrashLoopBackOff`とする。
- コンテナが連続して10分動いた時点で、バックオフを10秒に戻す。

<a id="sec-5-7-5"></a>
## 5.7.5 終了処理

1. Endpointsから外す。
2. preStopフックを実行する。
3. `SIGTERM`を送る。
4. `gracePeriodSeconds`だけ待つ。
5. プロセスが残っていれば`SIGKILL`を送る。
6. ネットワークを解放し、サンドボックスを破棄し、ボリュームを解放する。

<a id="sec-5-7-6"></a>
## 5.7.6 eviction

メモリまたはディスクの空きが閾値を下回った場合、優先度の低いPodから退去させる。退去では`SIGKILL`を直接送らず、通常の終了処理を行う。

## 関連

- [runtime](runtime.md)
- [network](network.md)
- [volume](volume.md)
- [04 node agent](../diagrams/04-node-agent.md)
