[仕様書の目次](../README.md) / [Ruby設計](README.md)

<a id="sec-6"></a>
# 6. データモデル

> 対象読者: Rubyの型システムの実装者、API実装者、審査者
>
> **Status:** Normative — version 0.2

単一schema DSLからRuby型、validator、codec、OpenAPI、RBS、DSL、diffを生成する規則を定義する。


<a id="sec-6-1"></a>
## 6.1 キー空間

```text
/registry/<resource>/<namespace>/<name>     Namespaced
/registry/<resource>/<name>                 Cluster-scoped
```

<a id="sec-6-2"></a>
## 6.2 内部表現

API 型は Ruby schema DSL の 1 定義を source of truth とする。

```ruby
resource :Pod, group: "", version: "v1", scope: :namespaced do
  spec do
    list  :containers, of: Container, required: true
    field :nodeName, String
    field :restartPolicy, String, default: "Always",
          one_of: %w[Always OnFailure Never]
    field :terminationGracePeriodSeconds, Integer, default: 30
  end

  status do
    field :phase, String
    list  :conditions, of: Condition
  end
end
```

schema compiler は次を同一 AST から決定的に生成する。

| 生成物 | 要件 |
|---|---|
| Ruby type | immutable value object、presence bit、型付き accessor、copy-with update |
| validator | required、enum、range、pattern、CEL、union、相関 validation |
| defaulting / conversion | external version ↔ hub ↔ storage version の純関数 |
| codec | JSON、YAML、CBOR、Kubernetes Protobuf の encode/decode |
| OpenAPI | v2/v3 schema と `x-kubernetes-*` extension |
| RBS | 全 public accessor、builder、controller block の型 |
| manifest DSL | resource、nested block、field、helper method |
| patch metadata | merge key、list/map/struct type、field set、managedFields path |
| diff | semantic equality、default-aware diff、status/spec 分離 |
| generator manifest | 入力 digest、compiler version、全生成 method 名、出力 digest |

`define_method` は schema compiler が生成する専用 Module 内だけで用いる。`method_missing`、
文字列 `eval`、`class_eval`、global class への monkey patch は禁止する。Ruby identifier にできない
JSON field は `field(:json_name)` accessor を必ず持ち、安全な alias を衝突しない場合だけ生成する。

built-in schema DSL は build 時に評価する。CRD は code として評価せず、構造化 OpenAPI schema を
同じ AST へ変換する。CRD が `Kernel`、`Object`、既存 method と衝突する field 名を含んでも、
global method table を変更してはならない。

resource object は field の「未指定」、明示 `null`、空配列、空 object を区別する。
unknown field は [§5.1.5](../api/api-server.md#sec-5-1-5) の pruning/preserve 規則に従って raw field map に保持する。
生成後の object と nested collection は deep freeze し、更新は structural sharing した新 object を返す。

<a id="sec-6-3"></a>
## 6.3 schema compiler の完全性

- 同じ schema AST と compiler version は byte-identical な生成物を返す
- generated source は repository に commit し、CI で再生成差分がないことを検査する
- OpenAPI field、Ruby accessor、RBS member、codec field、patch field の集合は一致しなければならない
- schema に存在する field の生成漏れ、存在しない field の生成、method collision は build error とする
- 全 GVK を空 object、最小 object、全 field object、unknown-field object で round-trip property test する
- upstream corpus と生成 OpenAPI/protobuf descriptor/discovery の構造差分を release gate でゼロにする

## Related

- [manifest dsl](manifest-dsl.md)
- [kubernetes api](../api/kubernetes-api.md)
- [formal methods](../verification/formal-methods.md)
