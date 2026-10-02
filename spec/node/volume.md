[仕様書の目次](../README.md) / [ノード](README.md)

<a id="sec-5-11"></a>
# 5.11 Volume（自作 core + CSI 互換）

> **Audience:** Volume実装者、Runtime実装者、セキュリティ設計者
>
> **Status:** Normative — version 0.2

built-in volume、CSI接続、lifecycle、ownership、projection、path securityを定義する。


> **Diagram:** [図 07 — Storage / Volume](../diagrams/07-storage-volume.md)

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

組込み backend は Ruby で `emptyDir`、`hostPath`、`configMap`、`secret`、`downwardAPI`、
`projected`、`image`、local PV、loop/device-mapper volume を実装する。外部 CSI driver は
Kubernetes CSI gRPC protocol の標準 extension point として接続できるが、VolumeManager、
state machine、mount、path validation、ownership、Secret 受渡しは Ruby が保持する。

<a id="sec-5-11-2"></a>
## 5.11.2 lifecycle と所有権

Volume は `Declared → Provisioned → Attached → Staged → Published → Unpublishing → Unstaged → Detached`
の順に遷移する。各遷移は operation token で冪等化し、controller/node の応答消失時は
`Unknown` として `ListVolumes`、mount table、device identity を照合する。process/VM が volume を
参照している間、unpublish、unmap、loop detach、workspace delete を行ってはならない。

`ReadWriteOncePod`、multi-attach prohibition、nodeAffinity、accessMode、reclaimPolicy、
WaitForFirstConsumer、online expansion、snapshot/clone、ephemeral volume を v1.36.2 と同じ条件で扱う。

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
