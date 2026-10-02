[仕様書の目次](../README.md) / [Ruby設計](README.md)

<a id="sec-6"></a>
# 6. データモデル

> 対象読者: Rubyの型システムの実装者、API実装者、審査者
>
> 状態: 規範、版0.2

1つのスキーマDSLから、Rubyの型、validator、コーデック、OpenAPI、RBS、DSL、diffを生成する規則を定義する。

<a id="sec-6-1"></a>
## 6.1 キー空間

```text
/registry/<resource>/<namespace>/<name>     Namespaced
/registry/<resource>/<name>                 Cluster-scoped
```

<a id="sec-6-2"></a>
## 6.2 内部表現

APIの型は、RubyのスキーマDSLによる1つの定義を正とする。

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

### 生成物

スキーマコンパイラは、次のものを同じASTから決定的に生成する。

| 生成物 | 要件 |
|---|---|
| Rubyの型 | 不変の値オブジェクト。presence bit、型付きのアクセサ、一部を変えたコピーを返す更新を持つ |
| validator | required、enum、range、pattern、CEL、union、フィールド間の相関の検査 |
| defaultingとconversion | 外部バージョン、hub、保存バージョンの間を変換する純関数 |
| コーデック | JSON、YAML、CBOR、Kubernetes Protobufのエンコードとデコード |
| OpenAPI | v2とv3のスキーマ、`x-kubernetes-*`拡張 |
| RBS | 公開しているすべてのアクセサ、builder、コントローラのブロックの型 |
| Manifest DSL | リソース、入れ子のブロック、フィールド、ヘルパーメソッド |
| patchのメタデータ | merge key、list・map・structの種別、field set、managedFieldsのパス |
| diff | 意味上の等価性、既定値を考慮したdiff、statusとspecの分離 |
| 生成マニフェスト | 入力のダイジェスト、コンパイラのバージョン、生成した全メソッドの名前、出力のダイジェスト |

### メソッド生成の制限

`define_method`は、スキーマコンパイラが生成する専用のModuleの中だけで使う。次のものは禁止する。

- `method_missing`
- 文字列の`eval`
- `class_eval`
- グローバルなクラスへのモンキーパッチ

Rubyの識別子にできないJSONフィールドには、必ず`field(:json_name)`形式のアクセサを用意する。安全な別名は、ほかの名前と衝突しない場合だけ生成する。

### 組み込みの型とCRD

組み込みのスキーマDSLはビルド時に評価する。

CRDはコードとして評価しない。構造化されたOpenAPIスキーマを、同じASTに変換する。CRDのフィールド名が`Kernel`、`Object`、既存のメソッドと衝突していても、グローバルなメソッドテーブルを変更してはならない。

### オブジェクトの表現

リソースオブジェクトは、フィールドについて次の4つを区別する。

- 未指定
- 明示的な`null`
- 空の配列
- 空のオブジェクト

未知のフィールドは、[5.1.5](../api/api-server.md#sec-5-1-5)のpruningとpreserveの規則に従い、生のフィールドマップに保持する。

生成したオブジェクトと入れ子のコレクションはdeep freezeする。更新は、変更のない部分を共有した新しいオブジェクトを返す。

<a id="sec-6-3"></a>
## 6.3 スキーマコンパイラの完全性

- 同じスキーマASTと同じコンパイラのバージョンからは、バイト単位で同一の生成物が得られる。
- 生成したソースはリポジトリにコミットする。再生成しても差分が出ないことをCIで検査する。
- OpenAPIのフィールド、Rubyのアクセサ、RBSのメンバ、コーデックのフィールド、patchのフィールドは、集合として一致しなければならない。
- スキーマにあるフィールドの生成漏れ、スキーマにないフィールドの生成、メソッド名の衝突は、ビルドエラーとする。
- すべてのGVKについて、round-tripのproperty testを行う。入力は、空のオブジェクト、最小のオブジェクト、全フィールドを持つオブジェクト、未知のフィールドを持つオブジェクトの4種類とする。
- upstreamのコーパスと、生成したOpenAPI、protobufのディスクリプタ、discoveryを比べる。リリースゲートでは構造の差分がゼロでなければならない。

## 関連

- [manifest dsl](manifest-dsl.md)
- [kubernetes api](../api/kubernetes-api.md)
- [formal methods](../verification/formal-methods.md)
