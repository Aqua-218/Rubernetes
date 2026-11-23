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

静的Podは `rubernetes-agent.static_pod_path` にマニフェストの絶対パスまたはディレクトリを指定する。ディレクトリではドットで始まるファイルを除く。確認間隔は `file_check_frequency_seconds` で指定でき、既定値は20秒。実行中の設定はノードの `/configz` の `kubeletconfig.fileCheckFrequency` で確認できる。単一ファイルの更新中に解析が失敗したときは直前のPodを維持し、ファイルの削除を検知するとPodを終了する。

`rubernetes-agent.static_pod_url` には HTTP または HTTPS のマニフェスト URL を指定できる。取得時に送るヘッダーは `static_pod_url_header` にヘッダー名から文字列配列へのマップで指定する。`http_check_frequency_seconds` の既定値は20秒で、取得は10秒、応答本文は10 MiBまでとする。応答は v1 の `Pod` または `PodList` を受け付ける。取得や検証に失敗したときは直前のマニフェストを維持し、空の `PodList` または本文が空の HTTP 200 を受け取ると URL 由来の Pod を終了する。ファイルソースと URL ソースは同時に利用でき、どちらの Pod も Node を所有者とするミラー Pod に状態を報告する。

ノードの `/configz` を閲覧する権限があれば、`kubeletconfig` の `staticPodURL`、`staticPodURLHeader`、`httpCheckFrequency` で稼働中の設定を確認できる。

### kubelet の設定ファイル

`rubernetes-agent --config /etc/rubernetes/agent.yaml --kubelet-config /etc/rubernetes/kubelet-config` は、従来の YAML を読み込んだあと、`kubelet.config.k8s.io/v1beta1` の `KubeletConfiguration` に明示した対応項目を上書きする。Rubernetes の YAML には API クライアント、ランタイム、ストレージなどの構成を指定する。パッケージの既定値を使う場合は `--config` に `KubeletConfiguration` を直接指定できる。

対応する入力は、静的 Pod のファイルと HTTP の各設定、同期周期、ノード状態の更新・報告周期、healthz と読み取り専用ポート、ノードリース、Pod 上限、Pod DNS、cgroup QoS と予約資源、CPU・メモリ・トポロジーのポリシー、イメージ GC、eviction、通常と Pod 優先度別のシャットダウン猶予、再起動バックオフの上限、`providerID`、API クライアントの `kubeAPIQPS` と `kubeAPIBurst`、`protectKernelDefaults`。相対パスの `staticPodPath` と `resolvConf` は設定ファイルのディレクトリを基準に解決する。空の `staticPodPath` はファイルからの静的 Pod の取得を無効にする。`resolvConf` に空文字を指定すると、ホスト設定を使う Pod はノードの IP ファミリーに対応するループバックを使う。空の `clusterDomain` では Pod の検索リストにクラスタードメインを加えない。`clusterDNS` が空なら組み込み DNS の待受アドレスを使う。組み込み DNS も無効なときは `ClusterFirst` の Pod をホスト設定にフォールバックし、Node と Pod に `MissingClusterDNS` イベントを記録する。省略と `null` は既存の設定を保持する。

`enableServer`、`address`、`port` は kubelet API のリスナーを設定する。ループバック以外で待ち受ける場合は Rubernetes の YAML で認証・認可を設定する。読み取り専用リスナーにはループバックアドレスを使用する。

`registerNode` の既定値は `true`。Node を初めて作るときは `registerWithTaints` の taint を適用し、再起動時は運用者やクラウドコントローラーが設定した状態を保持する。`registerNode: false` では管理者が Node を事前に作成する。Node の登録を待つ間も静的 Pod は起動でき、登録後はその Node に状態を報告する。

`serializeImagePulls` の既定値は `true` で、ノード全体で一度に一つのイメージを取得する。`maxParallelImagePulls: 2` のように 2 以上を設定し、`serializeImagePulls` を省略すると、指定件数まで並列取得する。この上限は同じノードの Native と CRI で共有する。ローカルにあるイメージを利用する Pod は取得枠が空くのを待つ必要がない。

`volumeStatsAggPeriod` は Pod ボリュームのディスク使用量を集計する間隔。既定値は `1m` で、`0s` でも既定値を使い、負の値で集計を無効にする。Summary API と `kubelet_volume_stats_*` メトリクスは最後に完了した集計を共有する。

`featureGates` はノードが実装するゲートを名前ごとに上書きする。ホスト対応のネイティブランタイムまたは CRI で `MemoryQoS` を有効にすると、`memoryThrottlingFactor` と `memoryReservationPolicy` を設定できる。ホスト対応のネイティブランタイムでは `protectKernelDefaults` に加え、`QOSReserved` と cgroup QoS が有効な場合の `qosReserved`、`memoryManagerPolicy: Static` の場合の `reservedMemory` を設定できる。`runtimeRequestTimeout` と `containerLogMonitorInterval` は Rubernetes の YAML で有効にした CRI に適用する。

`containerLogMaxSize` と `containerLogMaxFiles` はネイティブランタイムと CRI のログローテーションで使う。保存ファイル数は 2〜64。CRI を有効にした場合、`containerLogMaxWorkers` で同時に処理できるログ数を設定できる。既定値は 1 で、同じログのローテーションと削除は直列に行う。`podLogsDir` はホスト対応のネイティブランタイムと有効な CRI が Pod ログを置く絶対パス。`podPidsLimit` はホスト対応のネイティブランタイムで作る Pod に適用し、`-1` では PID の上限を設定しない。

ホスト対応のノードで `podsPerCore` が正の場合、ノードが検出した CPU 数との積を `maxPods` で上限にした値が Pod の容量になる。既定値の `0` では Pod の容量に `maxPods` を使う。`nodeStatusMaxImages` はノードの状態に報告するイメージ数の上限で、サイズの大きい順に既定で 50 件を報告する。`0` では `status.images` を省略し、`-1` では件数を制限しない。

`kubeAPIQPS` と `kubeAPIBurst` はノードから API サーバーへのリクエストを制限する。既定値は毎秒 50 件とバースト 100 件。`kubeAPIQPS: 0` は `/configz` に `0` と表示され、実際の上限は API グループとバージョンの組ごとに毎秒 5 件になる。`kubeAPIBurst: 0` では既定値の 100 件を使う。ノードのハートビートとイベント送信はそれぞれ別のクライアントを使う。

`/configz` が返す認証・認可、TLS、cgroup ドライバー、ランタイムエンドポイントなどの項目は、現在の値と一致する場合に読み戻した入力として受け付け、起動時に項目名を通知する。これらの値の変更や未知の項目は設定エラーになる。ファイルは毎回の起動時に読み込む。デプロイでは `--check-config` で検証したうえでファイルを置き換え、サービスを再起動する。

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

## Linuxカーネルの設定

`rubernetes-agent`の`protect_kernel_defaults: true`は、ノードの起動時にKubernetes v1.36.2が求める6つのsysctl値を検証し、不一致があれば起動を中断する。`false`を明示すると、異なる値を修正する。初期user namespaceで設定を省略した場合、ホストのsysctlへの書き込みは行わない。

エージェント自体がuser namespace内で動く場合、設定を省略すると値の修正を試みる。`KubeletInUserNamespace`を有効にした場合は、このときの書き込みエラーを無視する。値の読み取りや`protect_kernel_defaults: true`の検証が失敗した場合、起動を中断する。

## 関連

- [ランタイム](runtime.md)
- [ネットワーク](network.md)
- [ボリューム](volume.md)
- [04 ノードエージェント](../diagrams/04-node-agent.md)
