[仕様書の目次](../README.md) / [Ruby設計](README.md)

<a id="sec-3-5"></a>
# 3.5 Ruby Manifest DSL

> 対象読者: CLI利用者、Ruby実装者、審査者
>
> 状態: 規範、版0.2

Rubyのコードから標準のKubernetes JSONを生成するManifest DSLを定義する。DSLを隔離して実行する境界も定める。

## 動作

`rubectl apply -f app.rb` は Ruby ファイルを専用プロセスで評価し、標準 Kubernetes
JSON オブジェクトへコンパイルして既存 API に POST/PATCH する。API Server の要求・応答形式、
保存形式および wire protocol は DSL の有無で変化してはならない。

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

DSL のトップレベルメソッドとフィールドメソッドは [§6.2](schema-compiler.md#sec-6-2) の schema registry から
`define_method` で生成する。`method_missing` による GVK またはフィールド解決は禁止する。
条件分岐、反復、メソッド、定数および環境変数参照には Ruby の言語機能をそのまま用いる。

評価プロセスはネットワーク接続とクラスタ資格情報を持たず、生成結果だけを長さ付き IPC で
親の `rubectl` へ返す。既定の実行時間は 5 秒、最大出力は 16 MiB、最大リソース数は
10,000 とし、超過時は API 呼び出し前に失敗する。`--allow-code` の明示なしに、
信頼していない DSL ファイルを実行してはならない。

child mount namespace には DSL file、明示した import、Ruby runtime、必要な標準 library だけを
read-only で公開し、home、kubeconfig、SSH key、credential store を公開しない。環境変数は
`--env NAME` または project policy で allowlist した名前だけを継承する。上例は
`rubectl apply -f app.rb --allow-code --env REPLICAS` として実行する。

## Related

- [schema compiler](schema-compiler.md)
- [kubernetes api](../api/kubernetes-api.md)
- [controllers](../control-plane/controllers.md)
