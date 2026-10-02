[仕様書の目次](../README.md)

# 実装と納品の規則

> 対象読者: 実装者、レビュア、プロジェクトの管理者、リリース担当者

すべての要件をMUSTのまま完成させるための順序と、完成の判定を定義する。RubyとFFIの実装に適用する規約も定める。規約には、機械的に検査するものと、レビューで確認するものがある。

## Documents

| 文書 | 内容 |
|---|---|
| [実装計画](implementation-plan.md) | stage 00〜15、固定済み判断、1.0.0 release gate |
| [マイルストーン](milestones.md) | M0〜M9の累積成果物、exit criteria、required evidence |
| [Project Structure](project-structure.md) | repository tree、module境界、依存方向、artifact配置 |
| [Coding Standards](coding-standards.md) | syscall、error、concurrency、immutability、metaprogramming、proof traceability |

## Related

- [目的と完成基準](../foundation/goals-and-compatibility.md)
- [検証](../verification/README.md)
- [Kubernetes互換性試験](../verification/kubernetes-compatibility.md)
- [規範参照](../references.md)
