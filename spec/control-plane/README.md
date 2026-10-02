[仕様書の目次](../README.md)

# 制御面

> **Audience:** 分散システム実装者、Controller/Scheduler実装者、形式検証者

APIで受理したdesired stateを永続化し、watch eventからcontrollerとschedulerを駆動して
actual stateへ収束させるRuby製control planeを定義する。

## Component Flow

```mermaid
graph LR
    API["API Server"] -->|"MVCC operation"| Store["Store"]
    Store -->|"replicate"| Raft["Raft"]
    API -->|"list / watch"| Informer["Informer"]
    Informer -->|"deduplicated key"| Controllers["Controllers"]
    Informer -->|"unscheduled Pod"| Scheduler["Scheduler"]
    Controllers -->|"write desired delta"| API
    Scheduler -->|"bind"| API
```

## Documents

| 文書 | 内容 |
|---|---|
| [Store](store.md) | MVCC、revision、watch history、transaction |
| [Raft](raft.md) | election、WAL、commit、snapshot、membership |
| [Informer](informer.md) | Reflector、DeltaFIFO、Indexer、WorkQueue |
| [Controllers](controllers.md) | reconcile規約、built-in controller、Controller DSL |
| [Scheduler](scheduler.md) | Filter、Score、Bind、Preemption、plugin DSL |

## Related

- [Control Loop図](../diagrams/03-control-loop.md)
- [Node](../node/README.md)
- [形式仕様](../verification/formal-methods.md)

