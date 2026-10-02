[仕様書の目次](../README.md) / [基礎](README.md)

<a id="sec-11"></a>
# 11. 名称

> 対象読者: 全読者、リリース担当者
>
> 状態: 規範、版0.2

プロジェクト、モジュール、CLI、デーモン、拡張用ドメインの正式名称を定義する。

| 対象 | 名称 |
|---|---|
| プロジェクト | Rubernetes |
| Rubyのモジュール名前空間 | `Rubernetes` |
| CLI | `rubectl` |
| デーモンの実行ファイル | `rubernetes-apiserver`、`rubernetes-controller-manager`、`rubernetes-scheduler`、`rubernetes-agent`、`rubernetes-proxy` |
| 独自拡張のドメイン | `rubernetes.io` |

Kubernetes API上の標準のlabel、annotation、フィールド名は、互換性を保つために改名しない。`rubernetes.io`を使うのは独自拡張だけである。

## 関連

- [goals and compatibility](goals-and-compatibility.md)
- [references](../references.md)
