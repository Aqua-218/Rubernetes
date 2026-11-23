[仕様書の目次](../README.md) / [ノード](README.md)

<a id="sec-5-11"></a>
# 5.11 ボリューム

> 対象読者: ボリュームの実装者、ランタイムの実装者、セキュリティの設計者
>
> 状態: 規範、版0.2

組み込みのボリューム、CSIとの接続、ライフサイクル、所有権、投影、パスの安全性を定義する。中核は自作し、CSI互換のプラグインを接続できるようにする。

図は[図07 ストレージとボリューム](../diagrams/07-storage-volume.md)にある。

<a id="sec-5-11-1"></a>
## 5.11.1 インターフェース

```text
identity.capabilities                                  → capabilities
controller.create_volume(spec, token:)                 → volume_id
controller.delete_volume(id, token:)
controller.publish(id, node, token:)                   → attachment
controller.unpublish(id, node, token:)
controller.create_snapshot(id, token:)                 → snapshot_id
controller.expand(id, capacity, token:)                → capacity
node.stage(id, path, token:)
node.publish(id, pod, container_path, readonly:, token:)
node.unpublish(id, pod, container_path, token:)
node.unstage(id, path, token:)
node.stats(id)                                         → stats
recover                                                → recovery_report
```

組み込みのbackendは、次のボリュームをRubyで実装する。

- `emptyDir`
- `hostPath`
- `configMap`
- `secret`
- `downwardAPI`
- `projected`
- `image`
- local PV
- NFS、iSCSI、Fibre Channel のインラインボリュームと静的 PV
- loopとdevice-mapperによるボリューム

外部のCSIドライバは、Kubernetes CSIのgRPCプロトコルという標準の拡張点を通じて接続できる。ただし、VolumeManager、状態機械、マウント、パスの検証、所有権、Secretの受け渡しはRubyが保持する。

CSI の `volumeHandle` はドライバ固有の文字列として保持し、クラウドのリソースパスもそのままドライバに渡す。ノード上の管理 ID とマウント先は別に管理する。Kubernetes の CSI ボリュームでは、`NodeStageVolume`、`NodePublishVolume`、`NodeExpandVolume` のそれぞれが指定された Secret をノードの API クライアントでその都度取得する。再発行でも現在の値を取得し、復旧のために保存するのは Secret の名前と名前空間だけとする。

native ノードでは、新規の CSI ファイルシステムボリュームを `<pod_root>/<Pod UID>/volumes/kubernetes.io~csi/<volume spec 名>/mount` に公開する。volume spec 名は PVC を参照する場合は PV 名、CSI インラインボリュームでは Pod のボリューム名を使う。別の名前で同じ PVC を参照する Pod では、最初のボリュームをこのパスに、後続の参照をそれぞれ従来のパスに公開する。再起動後の再発行、統計取得、解放は保存済みの公開先を参照する。CSI に移行されたインラインボリュームとブロックボリュームには従来のパスを使う。

Pod のディレクトリをコンテナ内から参照する CSI ドライバには、ノードの実際の `pod_root` をドライバが参照するパスへマウント伝播付きで渡す。CSI hostpath のノード側ヘルスチェックが参照するパスは `/var/lib/kubelet/pods`。

native ノードの新規インライン NFS ボリュームは、`<pod_root>/<Pod UID>/volumes/kubernetes.io~nfs/<volume 名>` に公開する。公開先とステージの解放が済んだ後に、空になったディレクトリを削除する。既存の Pod は保存済みの公開先から解放する。

NFS は Linux の NFS クライアントでマウントし、PV の `mountOptions` と読み取り専用設定を適用する。iSCSI は Linux の iSCSI initiator と open-iscsi の `iscsiadm`、`iscsid` を使い、共有セッションは最後のボリュームの解放時にログアウトする。Fibre Channel はノードからアクセスできる LUN を WWN と LUN、または WWID で指定する。iSCSI と Fibre Channel の PV はネイティブ、CRI、MicroVM ランタイムで `volumeMode: Block` と `volumeDevices` を利用できる。

MicroVM は Pod が `volumeDevices` で参照するブロックボリュームを、起動時に virtio ブロックデバイスとして接続する。読み取り専用設定は Firecracker とゲスト内のコンテナの両方に適用する。ブロックボリュームを使う Pod はコールドブートで起動する。1 Pod あたりの上限は `microvm` が 11 個、`microvm-restricted` が 12 個。デバイスをノードから解放する前に VM の停止を確認する。

<a id="sec-5-11-2"></a>
## 5.11.2 ライフサイクルと所有権

ボリュームは次の順に遷移する。

```text
Declared → Provisioned → Attached → Staged → Published → Unpublishing → Unstaged → Detached
```

各遷移は操作トークンで冪等にする。controllerまたはnodeの応答が失われた場合は、状態を`Unknown`として扱う。そのうえで`ListVolumes`、マウントテーブル、デバイスのidentityを照合する。

プロセスまたはVMがボリュームを参照している間は、unpublish、unmap、loopのdetach、作業領域の削除を行ってはならない。

次の機能は、v1.36.2と同じ条件で扱う。

- `ReadWriteOncePod`
- multi-attachの禁止
- nodeAffinity
- accessMode
- reclaimPolicy
- WaitForFirstConsumer
- オンラインでの拡張
- スナップショットとクローン
- ephemeral volume

<a id="sec-5-11-3"></a>
## 5.11.3 投影とパスの安全性

- ConfigMap、Secret、downwardAPI、projectedの内容は、世代ごとのディレクトリに書く。更新はsymlinkのatomicな入れ替えで行う。
- SecretとServiceAccountのトークンはtmpfsだけに置く。swap、スナップショット、ログ、コアダンプ、ベースイメージに含めない。
- トークンは、audience、有効期限、PodのUIDに結び付ける。有効期間の80%に達した時点でローテートする。
- `subPath`とhostPathは、`openat2`とファイルディスクリプタで解決する。symlink、hardlink、マウントの差し替えによるTOCTOUを防ぐためである。
- hostPathがマウントポイントを直接指定する場合は、親を検証してから、そのファイルディスクリプタを起点に指定されたマウントだけを開く。
- `fsGroup`、SELinuxのラベル、読み取り専用、mountPropagationは、publishの前に適用する。適用に失敗した場合は、ワークロードを開始させない。
- マウント元、マウント先、マウントID、ファイルシステムのUUID、デバイスIDを、ランタイムの台帳に記録する。

## 関連

- [ノードエージェント](node-agent.md)
- [ランタイム](runtime.md)
- [07 ストレージとボリューム](../diagrams/07-storage-volume.md)
