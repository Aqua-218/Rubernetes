[仕様書インデックス](../README.md)

# Ruby Language Design

> **Audience:** Ruby実装者、DSL利用者、審査者

Rubyは単なる実装言語ではなく、API schema、宣言、制御ループ、scheduler、障害シナリオを
一つの型付きメタプログラミングモデルへ統合する。動的機能は自由な実行時解決ではなく、
検査可能なschema ASTと`define_method`による有限の生成面として使う。

## Generation Model

```mermaid
graph LR
    Schema["Schema DSL"] -->|"compile"| Registry["GVK / Field Registry"]
    Registry -->|"generate"| Types["Immutable Ruby Types"]
    Registry -->|"generate"| Codecs["Codec / Validation / OpenAPI"]
    Registry -->|"generate"| RBS["RBS"]
    Registry -->|"generate"| Manifest["Manifest DSL"]
    Registry -->|"type"| Controller["Controller DSL"]
    Registry -->|"type"| Scheduler["Scheduler DSL"]
    Registry -->|"type"| Scenario["Scenario DSL"]
```

## DSL Surfaces

| DSL | 定義箇所 | 生成・保証するもの |
|---|---|---|
| Schema | [Schema Compiler](schema-compiler.md) | type、validator、codec、default、OpenAPI、RBS、diff |
| Manifest | [Manifest DSL](manifest-dsl.md) | 標準Kubernetes JSON。API wire formatは変更しない |
| Controller | [Controllers](../control-plane/controllers.md#sec-5-5-8) | Informer、index、queue、ownershipの配線 |
| Scheduler | [Scheduler](../control-plane/scheduler.md#sec-5-6-6) | 型付きFilter/Score plugin |
| Scenario | [検証戦略](../verification/testing.md#sec-8-2) | 時系列障害注入と時相assertion |

## Metaprogramming Boundary

- `method_missing`でGVK、field、pluginを解決しない。
- `define_method`はschema compilerが所有する専用Moduleに限定する。
- 生成method一覧、入力schema digest、compiler version、生成物digestをmanifest化する。
- user supplied Ruby DSLはcluster credentialを持たない隔離processで評価する。
- Lean抽出コードを本番処理にせず、Ruby実装のtest oracleとして使う。

## Related

- [Coding Standards](../delivery/coding-standards.md)
- [Kubernetes API](../api/kubernetes-api.md)
- [形式仕様](../verification/formal-methods.md)

