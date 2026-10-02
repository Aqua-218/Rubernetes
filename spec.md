# Rubernetes仕様・設計書

Rubernetesの仕様と設計書の正本は、複数の文書からなる[`spec/`](spec/README.md)である。このファイルは入口の案内だけを載せる。以前から`spec.md`を参照している文書やIDEの設定が、そのまま使えるように残してある。

## 最初に読む文書

- [仕様・設計書の目次](spec/README.md)
- [目的、Kubernetes互換性、完成条件](spec/foundation/goals-and-compatibility.md)
- [全体アーキテクチャ](spec/foundation/architecture.md)
- [Rubyの言語設計](spec/ruby/README.md)
- [マイルストーンと完了の証拠](spec/delivery/milestones.md)
- [Kubernetes互換性試験](spec/verification/kubernetes-compatibility.md)
- [プロジェクト構成](spec/delivery/project-structure.md)
- [実装計画と受け入れ基準](spec/delivery/implementation-plan.md)
- [構成図集](spec/diagrams/README.md)

## 仕様の状態

| 項目 | 値 |
|---|---|
| 版 | 0.2 |
| 状態 | 実装基準ドラフト |
| 正本 | [`spec/`](spec/README.md) |
| 互換対象 | Kubernetes v1.36.2 |

個別文書間の優先順位、MUST/SHOULD/MAY、固定外部仕様の扱いは、
[文書規約](spec/foundation/document-conventions.md)に従う。

## Related

- [外部仕様と参考資料](spec/references.md)
- [検証戦略](spec/verification/README.md)
