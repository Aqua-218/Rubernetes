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

APIの型は[スキーマコンパイラ](../ruby/schema-compiler.md)の定義を正とする。Manifest DSLは[独立したCLIの層](../ruby/manifest-dsl.md)であり、標準のAPIオブジェクトを生成する。

## 関連

