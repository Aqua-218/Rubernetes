[仕様書の目次](../README.md)

# API仕様

> 対象読者: API実装者、クライアントの作者、互換性の検証者

Kubernetes v1.36.2が公開するAPIの境界と、その要求を処理するRuby製のAPIサーバを定義する。

## 文書

| 文書 | 内容 |
|---|---|
| [Kubernetes API](kubernetes-api.md) | リソースのコーパス、エンドポイント、ワイヤ形式、watch、patchとapply、互換性の判定 |
| [APIサーバ](api-server.md) | リクエスト処理の順序、認証と認可、流量制御、admission、監査、暗号化 |

## データとコード生成

API型のsource of truthは[Schema Compiler](../ruby/schema-compiler.md)であり、
manifest DSLは[独立したCLI層](../ruby/manifest-dsl.md)として標準API objectを生成する。

## Related

- [Store](../control-plane/store.md)
- [API Server図](../diagrams/01-api-server.md)
- [互換性試験](../verification/testing.md)

