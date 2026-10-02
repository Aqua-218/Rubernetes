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
- loopとdevice-mapperによるボリューム

外部のCSIドライバは、Kubernetes CSIのgRPCプロトコルという標準の拡張点を通じて接続できる。ただし、VolumeManager、状態機械、マウント、パスの検証、所有権、Secretの受け渡しはRubyが保持する。

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
## 5.11.3 投影と path security

- ConfigMap、Secret、downwardAPI、projected は世代 directory へ書き、symlink の atomic swap で更新する
- Secret と ServiceAccount token は tmpfs にだけ置き、swap、snapshot、log、core dump、base image に含めない
- token は audience、expiry、Pod UID に bind し、有効期間の 80% 到達時に rotate する
- `subPath` と hostPath は `openat2` と file descriptor で解決し、symlink/hardlink/mount replacement の TOCTOU を防ぐ
- `fsGroup`、SELinux label、read-only、mountPropagation を publish 前に適用し、失敗時に workload gate を開かない
- mount source、target、mount ID、filesystem UUID、device ID を runtime ledger に記録する

## Related

- [node agent](node-agent.md)
- [runtime](runtime.md)
- [07 storage volume](../diagrams/07-storage-volume.md)
