[仕様書の目次](../README.md)

# API仕様

> 対象読者: API実装者、クライアントの作者、互換性の検証者

Kubernetes v1.36.2が公開するAPIの境界と、その要求を処理するRuby製のAPIサーバを定義する。

## 文書

| 文書 | 内容 |
|---|---|
| [Kubernetes API](kubernetes-api.md) | resource corpus、endpoint、wire format、watch、patch/apply、互換判定 |
| [API Server](api-server.md) | request pipeline、authn/authz、APF、admission、audit、encryption |

## Data and Code Generation

API型のsource of truthは[Schema Compiler](../ruby/schema-compiler.md)であり、
manifest DSLは[独立したCLI層](../ruby/manifest-dsl.md)として標準API objectを生成する。

## Related

- [Store](../control-plane/store.md)
- [API Server図](../diagrams/01-api-server.md)
- [互換性試験](../verification/testing.md)

