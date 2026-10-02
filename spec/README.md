# Rubernetes仕様・設計書

> 対象読者: 利用者、実装者、検証者、運用者、審査者
>
> 版: 0.2
>
> 状態: 実装基準ドラフト

Rubernetesは、Kubernetes v1.36.2と外部から観測して互換なLinuxコンテナオーケストレータである。制御面からコンテナ実行、ネットワークまでをRuby中心で独立に実装する。このディレクトリが仕様と設計書の正本であり、このページが入口である。

## 文書の全体像

```mermaid
graph TD
    Hub["仕様・設計書の目次"]
    Hub -->|"目的と全体構造"| Foundation["基礎"]
    Hub -->|"Rubyの言語設計"| RubyDesign["Ruby設計"]
    Hub -->|"Kubernetes API"| API["API"]
    Hub -->|"分散制御"| ControlPlane["制御面"]
    Hub -->|"Pod実行"| Node["ノード"]
    Hub -->|"証明と試験"| Verification["検証"]
    Hub -->|"実装と完成判定"| Delivery["実装と納品"]
    Hub -->|"構成図"| Diagrams["構成図"]
    Hub -->|"固定した外部仕様"| References["規範参照"]
```

## 目的別の読み方

| 目的 | 読む順序 |
|---|---|
| 全体像を知りたい | [目的と互換性](foundation/goals-and-compatibility.md) → [アーキテクチャ](foundation/architecture.md) → [全景図](diagrams/00-overview.md) |
| Rubyらしさを見たい | [Ruby設計](ruby/README.md) → [スキーマコンパイラ](ruby/schema-compiler.md) → [コントローラDSL](control-plane/controllers.md) |
| Kubernetes互換を実装する | [Kubernetes API](api/kubernetes-api.md) → [APIサーバ](api/api-server.md) → [検証戦略](verification/testing.md) |
| コンテナ実行を実装する | [ノードエージェント](node/node-agent.md) → [ランタイム](node/runtime.md) → [ネットワーク](node/network.md) → [ボリューム](node/volume.md) |
| 正しさを確認する | [形式仕様](verification/formal-methods.md) → [検証戦略](verification/testing.md) → [検証図](diagrams/08-verification.md) |
| 実装順と完成条件を確認する | [マイルストーン](delivery/milestones.md) → [実装計画](delivery/implementation-plan.md) → [コーディング規約](delivery/coding-standards.md) |
| リポジトリの構造を確認する | [プロジェクト構成](delivery/project-structure.md) → [アーキテクチャ](foundation/architecture.md) |
| upstreamのテストを導入する | [Kubernetes互換性試験](verification/kubernetes-compatibility.md) → [検証戦略](verification/testing.md) |

## 文書群

| 文書群 | 扱う内容 | 目次 |
|---|---|---|
| 基礎 | 文書規約、目的、互換性の境界、用語、全体構造、名称 | [foundation/](foundation/README.md) |
| Ruby設計 | Manifest DSL、Schema DSL、メタプログラミングによる生成の境界 | [ruby/](ruby/README.md) |
| API | Kubernetes APIとAPIサーバ | [api/](api/README.md) |
| 制御面 | ストア、Raft、informer、コントローラ、スケジューラ | [control-plane/](control-plane/README.md) |
| ノード | ノードエージェント、ランタイム、ネットワーク、サービスプロキシ、ボリューム | [node/](node/README.md) |
| 検証 | TLA+、Lean、upstreamのConformanceとe2e、差分試験、障害注入、実機でのゲート | [verification/](verification/README.md) |
| 実装と納品 | マイルストーン、リポジトリ構造、実装順、リリースゲート、コーディング規約 | [delivery/](delivery/README.md) |
| 構成図 | 00〜08の構成図 | [diagrams/](diagrams/README.md) |
| 規範参照 | 固定する外部仕様と設計の由来 | [references.md](references.md) |

## 規範上の規則

- 本文中のMUST、MUST NOT、SHOULD、MAYと、これらの語が付かない規範文は、[文書規約](foundation/document-conventions.md)に従う。
- 同じ事項について本文と図が食い違う場合は、本文を正とする。
- Kubernetes v1.36.2の外部から観測できる挙動と本文が食い違う場合は、互換な挙動を優先する。ただし、明示したLinuxプラットフォームの境界は除く。
- 仕様を変更するときは、本文、図、機械可読のコーパス、形式仕様、テストを同じ変更単位で更新する。

## 全文書の一覧

### Foundation

- [文書規約](foundation/document-conventions.md)
- [目的・互換性・規模](foundation/goals-and-compatibility.md)
- [用語集](foundation/glossary.md)
- [アーキテクチャ](foundation/architecture.md)
- [名称](foundation/naming.md)

### Ruby Design and API

- [Ruby Design Overview](ruby/README.md)
- [Ruby Manifest DSL](ruby/manifest-dsl.md)
- [Schema Compiler](ruby/schema-compiler.md)
- [Kubernetes API](api/kubernetes-api.md)
- [API Server](api/api-server.md)

### Control Plane and Node

- [Store](control-plane/store.md)
- [Raft](control-plane/raft.md)
- [Informer](control-plane/informer.md)
- [Controllers](control-plane/controllers.md)
- [Scheduler](control-plane/scheduler.md)
- [Node Agent](node/node-agent.md)
- [Runtime](node/runtime.md)
- [Network](node/network.md)
- [Service Proxy](node/service-proxy.md)
- [Volume](node/volume.md)

### Verification and Delivery

- [形式仕様](verification/formal-methods.md)
- [検証戦略](verification/testing.md)
- [Kubernetes互換性試験](verification/kubernetes-compatibility.md)
- [マイルストーンと完了証拠](delivery/milestones.md)
- [Project Structure](delivery/project-structure.md)
- [実装計画とrelease gate](delivery/implementation-plan.md)
- [Coding Standards](delivery/coding-standards.md)
- [規範参照](references.md)

### Diagrams

- [00 全景](diagrams/00-overview.md)
- [01 API Server](diagrams/01-api-server.md)
- [02 Storage / Raft](diagrams/02-storage-raft.md)
- [03 制御ループ](diagrams/03-control-loop.md)
- [04 Node Agent](diagrams/04-node-agent.md)
- [05 Runtime](diagrams/05-runtime.md)
- [06 Network](diagrams/06-network.md)
- [07 Storage / Volume](diagrams/07-storage-volume.md)
- [08 Verification](diagrams/08-verification.md)

## Related

- [ルート案内](../spec.md)
- [規範参照](references.md)
