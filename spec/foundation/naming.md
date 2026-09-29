[仕様書インデックス](../README.md) / [foundation](README.md)

<a id="sec-11"></a>
# 11. 名称

> **Audience:** 全読者、release担当者
>
> **Status:** Normative — version 0.2

project、module、CLI、daemon、extension domainの正式名称を定義する。


プロジェクト名は **Rubernetes**、Ruby module namespace は `Rubernetes`、
CLI は `rubectl` とする。daemon binary は `rubernetes-apiserver`、
`rubernetes-controller-manager`、`rubernetes-scheduler`、`rubernetes-agent`、
`rubernetes-proxy` とする。Kubernetes API 上の標準 label、annotation、field 名は
互換性のため改名せず、独自 extension の domain だけに `rubernetes.io` を用いる。

## Related

- [goals and compatibility](goals-and-compatibility.md)
- [references](../references.md)
