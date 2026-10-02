[仕様書の目次](../README.md)

# Architecture Diagrams

> **Audience:** 全読者、アーキテクト、実装者、審査者

本文の構造と処理経路を示すMermaid図をまとめる。図と規範本文が食い違う場合は本文を正とする。

## Diagram Index

| ID | 図 | 対応本文 |
|---|---|---|
| 00 | [全景](00-overview.md) | [Architecture](../foundation/architecture.md) |
| 01 | [API Server](01-api-server.md) | [API Server](../api/api-server.md) |
| 02 | [Storage / Raft](02-storage-raft.md) | [Store](../control-plane/store.md)、[Raft](../control-plane/raft.md) |
| 03 | [制御ループ](03-control-loop.md) | [Informer](../control-plane/informer.md)、[Controllers](../control-plane/controllers.md) |
| 04 | [Node Agent](04-node-agent.md) | [Node Agent](../node/node-agent.md) |
| 05 | [Runtime](05-runtime.md) | [Runtime](../node/runtime.md) |
| 06 | [Network](06-network.md) | [Network](../node/network.md)、[Service Proxy](../node/service-proxy.md) |
| 07 | [Storage / Volume](07-storage-volume.md) | [Volume](../node/volume.md) |
| 08 | [Verification](08-verification.md) | [Formal Methods](../verification/formal-methods.md)、[Testing](../verification/testing.md) |

## Related

- [Foundation Architecture](../foundation/architecture.md)
- [仕様書インデックス](../README.md)
