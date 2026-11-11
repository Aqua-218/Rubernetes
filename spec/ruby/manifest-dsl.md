[仕様書の目次](../README.md) / [Ruby設計](README.md)

<a id="sec-3-5"></a>
# 3.5 Ruby Manifest DSL

> 対象読者: CLI利用者、Ruby実装者、審査者
>
> 状態: 規範、版0.3

Rubyのコードから標準のKubernetes JSONを生成するManifest DSLを定義する。DSLを隔離して実行する境界も定める。

## 動作

`rubectl apply -f app.rb`は、Rubyファイルを専用のプロセスで評価する。評価結果を標準のKubernetes JSONオブジェクトにコンパイルし、既存のAPIにPOSTまたはPATCHする。

APIサーバの要求と応答の形式、保存形式、ワイヤプロトコルは、DSLを使っても使わなくても変わってはならない。

```ruby
def production? = ENV["APP_ENV"] == "production"

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

トップレベルの`def`は、ファイルの中のすべてのブロックから呼べる。フィールドと同じ名前のメソッドを定義した場合は、そのフィールドを持つ型のブロックに入る時点でエラーにする。ブロックの中ではその名前がフィールドの設定を意味し、メソッドは呼ばれないからである。

## 値の検査

フィールドに渡した値は、組み立てる時点でスキーマと照合する。APIを呼び出す前に、次のことを行う。

- オブジェクト型のフィールドに渡したハッシュのキーを、JSONのフィールド名に変換する。`target_port`は`targetPort`になる。JSONの名前をそのまま書いてもよい。入れ子と配列の中にも同じ規則を適用する。
- 型にないキーはエラーにする。メッセージには、場所、型の名前、最も近いフィールド名を含める。
- マップ型のフィールドのキーは変換しない。ラベル、アノテーション、ConfigMapの`data`がこれにあたる。
- 固有のフィールドを持たない型の値は、そのまま通す。Quantity、IntOrString、任意のJSONがこれにあたる。

エラーは、マニフェストのファイル名と行番号を先頭に付けて1行で報告する。

```text
app.rb:8: spec.ports[0]: ServicePort has no field "taget_port" (did you mean "target_port"?)
app.rb:2: Deployment has no field or helper "replica" (did you mean "replicas"?)
```

フィールドにブロックを渡した場合、すでにある値に追記する。同じフィールドを2回のブロックに分けて書いてもよい。

## ワークロードの短い書き方

Podテンプレートを持つ型のブロックでは、次のメソッドが使える。対象は、Pod、Deployment、StatefulSet、DaemonSet、ReplicaSet、ReplicationController、Job、CronJobである。対象かどうかは、型のスキーマにPodSpecがあるかどうかで決める。型の名前の一覧は持たない。

| メソッド | 書き込む先 |
|---|---|
| `container NAME, image:, **fields do ... end` | `containers`に1つ追加する |
| `init_container NAME, image:, **fields do ... end` | `initContainers`に1つ追加する |
| `volume NAME, from: configmap(...)` | `volumes`に追加する。`from:`がなく、ほかの指定もない場合は`emptyDir`にする |
| `pod do ... end` | PodSpecのそのほかのフィールドを書く |
| `anti_affinity on: KEY` | 同じワークロードのPod同士を、`KEY`のトポロジで分ける |

`container`のブロックでは、Containerのフィールドに加えて次のメソッドが使える。

| メソッド | 書き込む先 |
|---|---|
| `port NUMBER, name:, protocol:` | `ports` |
| `cpu request:, limit:`、`memory request:, limit:` | `resources` |
| `env NAME, VALUE` | `env` |
| `env from: configmap(NAME)`、`env from: secret(NAME)` | `envFrom` |
| `env NAME, from: secret(NAME), key: KEY` | `env`の`valueFrom` |
| `mount VOLUME, at: PATH, read_only:` | `volumeMounts` |

`configmap(NAME)`と`secret(NAME)`は、参照先を表す値を返す。トップレベルの`secret`はSecretを宣言するメソッドなので、参照を表すのはブロックの中だけである。

ブロックが終わった時点で、次の値を補う。

- `selector`が必須の型で`selector`を書いていない場合、テンプレートのラベルを選ぶ`selector`を作る。テンプレートにラベルがなければ`app: <名前>`を使う。
- `selector`の`matchLabels`を、テンプレートのラベルに加える。
- JobとCronJobで`restartPolicy`を書いていない場合、`Never`にする。APIが受け付ける既定値がないためである。

これらのメソッドが書くのは通常のフィールドである。生成されたフィールドメソッドと同じブロックで併用できる。短い書き方が用意していないフィールドは、フィールドメソッドで書く。

## 出力の確認

`rubectl render -f app.rb --allow-code`は、`apply`が送るオブジェクトを標準出力に書く。APIには接続しない。`-o yaml`の出力は、そのまま`kubectl apply -f -`に渡せる。`--env`で渡した値も、出力にはそのまま現れる。

## 評価プロセスの制限

評価プロセスは、ネットワーク接続とクラスタの資格情報を持たない。生成結果だけを、長さ付きのIPCで親の`rubectl`に返す。

| 項目 | 既定の上限 |
|---|---|
| 実行時間 | 5秒 |
| 出力の大きさ | 16 MiB |
| リソースの数 | 10,000 |

上限を超えた場合は、APIを呼び出す前に失敗する。

信頼していないDSLファイルを、`--allow-code`の明示なしに実行してはならない。

## 評価プロセスに見せるもの

子プロセスのmount namespaceには、次のものだけを読み取り専用で公開する。

- DSLファイル
- 明示したimport
- Rubyのランタイム
- 必要な標準ライブラリ

ホームディレクトリ、kubeconfig、SSH鍵、資格情報のストアは公開しない。

環境変数は、`--env NAME`で指定した名前か、プロジェクトのポリシーで許可した名前だけを引き継ぐ。上の例は次のように実行する。

```sh
rubectl apply -f app.rb --allow-code --env REPLICAS
```

## 関連

- [スキーマコンパイラ](schema-compiler.md)
- [Kubernetes API](../api/kubernetes-api.md)
- [コントローラ](../control-plane/controllers.md)
