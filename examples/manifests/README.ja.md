# Rubyで書くマニフェストの例

[English](README.md) | 日本語

マニフェストをRubyで書く例です。出力は標準のKubernetesオブジェクトなので、本物の`kubectl`にそのまま渡せます。規則は[仕様](../../spec/ruby/manifest-dsl.md)にあります。

| ファイル | 内容 |
|---|---|
| [web.rb](web.rb) | ConfigMap、Deployment、Service。環境変数で本番用と開発用を切り替える |
| [tenants.rb](tenants.rb) | テナントの一覧から、namespace、ResourceQuota、Deploymentを繰り返し作る |
| [nightly_report.rb](nightly_report.rb) | Secretと作業用ボリュームを使うCronJob |

## 使い方

`render`は、クラスタに接続せずに出力だけを確認します。

```sh
ruby -Ilib exe/rubectl render -f examples/manifests/web.rb --allow-code -o yaml
```

適用するには、`render`の出力を`kubectl`に渡すか、`rubectl apply`を使います。

```sh
ruby -Ilib exe/rubectl render -f examples/manifests/web.rb --allow-code -o yaml | kubectl apply -f -
APP_ENV=production ruby -Ilib exe/rubectl apply -f examples/manifests/web.rb --allow-code --env APP_ENV
```

Rubyファイルは、ネットワークとクラスタの資格情報を持たない別プロセスで評価されます。環境変数は`--env`で名前を挙げたものだけが渡ります。

## YAMLとの違い

Deploymentは次のように書けます。`selector`と、それに対応するテンプレートのラベルは書かなくても補われます。

```ruby
deployment "web" do
  replicas 3

  container "nginx", image: "nginx:1.27" do
    port 80
    cpu request: "100m", limit: "500m"
    env from: configmap("web-config")
    readiness_probe http_get: {path: "/", port: 80}, period_seconds: 5
  end
end
```

フィールドはスキーマと照合されます。書き間違いは、適用する前に、行番号と候補つきで分かります。

```text
web.rb:9: containers.nginx.readinessProbe.httpGet: HTTPGetAction has no field "pathh" (did you mean "path"?)
web.rb:2: Deployment has no field or helper "replica" (did you mean "replicas"?)
```

繰り返しや条件分岐、共通部分のメソッド化には、Rubyをそのまま使います。テンプレート言語は要りません。[tenants.rb](tenants.rb)がその例です。
