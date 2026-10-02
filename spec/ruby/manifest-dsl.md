[仕様書の目次](../README.md) / [Ruby設計](README.md)

<a id="sec-3-5"></a>
# 3.5 Ruby Manifest DSL

> 対象読者: CLI利用者、Ruby実装者、審査者
>
> 状態: 規範、版0.2

Rubyのコードから標準のKubernetes JSONを生成するManifest DSLを定義する。DSLを隔離して実行する境界も定める。

## 動作

`rubectl apply -f app.rb`は、Rubyファイルを専用のプロセスで評価する。評価結果を標準のKubernetes JSONオブジェクトにコンパイルし、既存のAPIにPOSTまたはPATCHする。

APIサーバの要求と応答の形式、保存形式、ワイヤプロトコルは、DSLを使っても使わなくても変わってはならない。

```ruby
deployment "web", namespace: "prod" do
  replicas ENV.fetch("REPLICAS", 3).to_i

  container "nginx", image: "nginx:1.25" do
    port 80
    cpu request: "100m", limit: "500m"
    memory request: "128Mi", limit: "256Mi"
    env from: configmap("app-config")
  end

  anti_affinity(on: "kubernetes.io/hostname") if production?
end
```

## メソッドの生成

DSLのトップレベルメソッドとフィールドメソッドは、[6.2](schema-compiler.md#sec-6-2)のスキーマレジストリから`define_method`で生成する。`method_missing`でGVKやフィールドを解決することは禁止する。

条件分岐、反復、メソッド、定数、環境変数の参照には、Rubyの言語機能をそのまま使う。

## 評価プロセスの制限

評価プロセスは、ネットワーク接続とクラスタの資格情報を持たない。生成結果だけを、長さ付きのIPCで親の`rubectl`に返す。

| 項目 | 既定の上限 |
|---|---|
| 実行時間 | 5秒 |
| 出力の大きさ | 16 MiB |
| リソースの数 | 10,000 |

上限を超えた場合は、APIを呼び出す前に失敗する。

信頼していないDSLファイルを、`--allow-code`の明示なしに実行してはならない。

child mount namespace には DSL file、明示した import、Ruby runtime、必要な標準 library だけを
read-only で公開し、home、kubeconfig、SSH key、credential store を公開しない。環境変数は
`--env NAME` または project policy で allowlist した名前だけを継承する。上例は
`rubectl apply -f app.rb --allow-code --env REPLICAS` として実行する。

## Related

- [schema compiler](schema-compiler.md)
- [kubernetes api](../api/kubernetes-api.md)
- [controllers](../control-plane/controllers.md)
