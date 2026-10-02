[仕様書の目次](../README.md)

# 実装と納品の規則

> 対象読者: 実装者、レビュア、プロジェクトの管理者、リリース担当者

すべての要件をMUSTのまま完成させるための順序と、完成の判定を定義する。RubyとFFIの実装に適用する規約も定める。規約には、機械的に検査するものと、レビューで確認するものがある。

## 文書

| 文書 | 内容 |
|---|---|
| [実装計画](implementation-plan.md) | stage 00〜15、確定済みの判断、1.0.0のリリースゲート |
| [マイルストーン](milestones.md) | M0〜M9の累積的な成果物、完了条件、必要な証拠 |
| [プロジェクト構成](project-structure.md) | リポジトリのツリー、モジュールの境界、依存の方向、成果物の配置 |
| [コーディング規約](coding-standards.md) | システムコール、エラー、並行性、不変性、メタプログラミング、証明との対応 |

## 関連

- [目的と完成基準](../foundation/goals-and-compatibility.md)
- [検証](../verification/README.md)
- [Kubernetes互換性試験](../verification/kubernetes-compatibility.md)
- [規範参照](../references.md)
