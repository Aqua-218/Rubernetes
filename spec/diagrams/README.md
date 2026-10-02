[仕様書の目次](../README.md)

# 構成図

> 対象読者: 全読者、アーキテクト、実装者、審査者

本文が定める構造と処理の経路を、Mermaidの図で示す。図と本文が食い違う場合は、本文を正とする。

## 図の一覧

| 番号 | 図 | 対応する本文 |
|---|---|---|
| 00 | [全景](00-overview.md) | [アーキテクチャ](../foundation/architecture.md) |
| 01 | [APIサーバ](01-api-server.md) | [APIサーバ](../api/api-server.md) |
| 02 | [ストレージとRaft](02-storage-raft.md) | [ストア](../control-plane/store.md)、[Raft](../control-plane/raft.md) |
| 03 | [制御ループ](03-control-loop.md) | [informer](../control-plane/informer.md)、[コントローラ](../control-plane/controllers.md) |
| 04 | [ノードエージェント](04-node-agent.md) | [ノードエージェント](../node/node-agent.md) |
| 05 | [ランタイム](05-runtime.md) | [ランタイム](../node/runtime.md) |
| 06 | [ネットワーク](06-network.md) | [ネットワーク](../node/network.md)、[サービスプロキシ](../node/service-proxy.md) |
| 07 | [ストレージとボリューム](07-storage-volume.md) | [ボリューム](../node/volume.md) |
| 08 | [検証](08-verification.md) | [形式仕様](../verification/formal-methods.md)、[検証戦略](../verification/testing.md) |

## Related

- [Foundation Architecture](../foundation/architecture.md)
- [仕様書インデックス](../README.md)
