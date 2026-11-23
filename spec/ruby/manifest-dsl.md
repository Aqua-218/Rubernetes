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
- 配列、オブジェクト、数値、真偽値、文字列はスキーマの型を確認する。たとえば `replicas "three"` は `spec.replicas: expected integer, got String` と報告する。
- 型にないキーはエラーにする。メッセージには、場所、型の名前、最も近いフィールド名を含める。
- マップ型のフィールドのキーは変換しない。ラベル、アノテーション、ConfigMapの`data`がこれにあたる。
- 固有のフィールドを持たない型の値は、そのまま通す。Quantity、IntOrString、任意のJSONがこれにあたる。

エラーは、マニフェストのファイル名と行番号を先頭に付けて1行で報告する。

```text
app.rb:8: spec.ports[0]: ServicePort has no field "taget_port" (did you mean "target_port"?)
app.rb:2: Deployment has no field or helper "replica" (did you mean "replicas"?)
```

フィールドにブロックを渡した場合、すでにある値に追記する。同じフィールドを2回のブロックに分けて書いてもよい。

宣言全体に適用する条件は `check` のブロックに書ける。各 Ruby ファイルの評価後、そのファイルで生成したリソースを凍結済みの配列としてブロックに渡す。条件より後に書いた宣言も参照できる。ブロックが偽を返すか例外を送出すると、`render`、`plan`、`apply` は条件名と宣言行を表示する。複数ファイルの `apply` では全ファイルの評価が成功した後に書き込みを始める。

```ruby
check "公開する Service には担当チームを指定する" do |resources|
  resources.select { |r| r["kind"] == "Service" && r.dig("spec", "type") == "LoadBalancer" }
           .all? { |r| r.dig("metadata", "labels", "team") }
end
```

## ワークロードの短い書き方

Podテンプレートを持つ型のブロックでは、次のメソッドが使える。対象は、Pod、Deployment、StatefulSet、DaemonSet、ReplicaSet、ReplicationController、Job、CronJobである。対象かどうかは、型のスキーマにPodSpecがあるかどうかで決める。型の名前の一覧は持たない。

| メソッド | 書き込む先 |
|---|---|
| `container NAME, image:, **fields do ... end` | `containers`に1つ追加する |
| `init_container NAME, image:, **fields do ... end` | `initContainers`に1つ追加する |
| `sidecar NAME, image:, **fields do ... end` | `initContainers` に `restartPolicy: Always` で追加する。起動順は `init_container` と `sidecar` の宣言順で決まる |
| `volume NAME, from: configmap(...)` | `volumes`に追加する。`from:`がなく、ほかの指定もない場合は`emptyDir`にする |
| `volume_claim_template NAME, **metadata do ... end` | StatefulSet の `spec.volumeClaimTemplates` に追加し、同じ StatefulSet 内で `mount` や `device` に渡せる参照を返す。ブロックには PersistentVolumeClaim のフィールドを書ける |
| `pod do ... end` | PodSpecのそのほかのフィールドを書く |
| `spread_across KEY, max_skew: 1, when_unsatisfiable: :do_not_schedule` | `topologySpreadConstraints` にワークロードの Pod セレクターを含む制約を追加する。ソフト制約には `:schedule_anyway` を指定し、同じトポロジーキーと方式の重複は宣言行で報告する |
| `anti_affinity on: KEY` | 同じワークロードの Pod 同士を、ノードラベル `KEY` の値が異なる場所に配置する。ワークロードのセレクターを `matchExpressions` も含めて使うため、たとえば同じアプリの中でワーカーだけを分散できる |

`container`のブロックでは、Containerのフィールドに加えて次のメソッドが使える。

| メソッド | 書き込む先 |
|---|---|
| `port NUMBER, name:, protocol:` | `ports` |
| `http_probe :readiness, port: :http, path: "/ready", period_seconds: 5` | `readinessProbe.httpGet` と `periodSeconds`。`:startup` と `:liveness` も指定できる。名前付きポートは同じコンテナの TCP ポートと照合し、数値ポートは 1 から 65535 までを直接指定できる。既定のパスは `/`、通信方式は HTTP。`scheme: :https` で HTTPS を使う |
| `tcp_probe :startup, port: :sql` | `startupProbe.tcpSocket`。HTTP と同様に同じコンテナの名前付き TCP ポートを指定できる |
| `http_probe :readiness, port: :http, headers: {Host: "catalog.example.test"}` | `httpGet.httpHeaders`。同名のヘッダーを複数送るときは値を配列で渡す。Host を指定しても接続先の Pod IP は維持される |
| `grpc_probe :readiness, port: 9000, service: "catalog"` | `readinessProbe.grpc`。数値ポートが必須。サービス名は省略できる |
| `exec_probe :liveness, command: ["pg_isready", "-q"]` | `livenessProbe.exec.command`。引数は文字列の配列で渡す |
| `cpu request:, limit:`、`memory request:, limit:`、`ephemeral_storage request:, limit:` | コンテナの `resources.requests` と `resources.limits` |
| `env_field "POD_IP", "status.podIP"` | `env[].valueFrom.fieldRef`。ラベルは `label: "example.com/team"`、注釈は `annotation: "example.com/revision"` でキーを指定できる |
| `env_resource "CPU_MILLICORES", "requests.cpu", divisor: "1m"` | `env[].valueFrom.resourceFieldRef`。既定の参照先は同じコンテナで、別のコンテナを参照するときは `container:` に名前を指定する |
| `env NAME, VALUE` | `env` |
| `env from: configmap(NAME)`、`env from: secret(NAME)` | `envFrom` |
| `env NAME, from: secret(NAME), key: KEY` | `env`の`valueFrom` |
| `mount CONFIG, at: PATH`、`mount NAME, from: CONFIG, at: PATH` | ConfigMap または Secret のボリュームを Pod に一度追加し、コンテナに読み取り専用でマウントする |
| `mount NAME, from: [CONFIG, SECRET], at: PATH` | 配列順の `projected.sources` を生成し、同じディレクトリに読み取り専用でマウントする。同名のファイルには後のソースの内容とモードを使う。`volume NAME, from: 配列` でも宣言できる |
| `mount CLAIM, at: PATH, read_only:` | 宣言した PersistentVolumeClaim をマウントする。同じ Pod の複数のコンテナで共有でき、読み取り専用の指定はコンテナごとに行う |
| `device CLAIM, at: PATH` | `volumeMode: Block` の PersistentVolumeClaim をコンテナの `volumeDevices` に追加する。ファイルシステムとブロックの指定を取り違えると、宣言の行番号にエラーを表示する |
| `mount VOLUME, at: PATH, read_only:` | `volumeMounts` |
| `device VOLUME, at: PATH` | 名前を指定して `volumeDevices` に追加する |

`cpu`、`memory`、`ephemeral_storage` の `request:` と `limit:` には、0 以上の Kubernetes Quantity を指定する。たとえば `ephemeral_storage limit: "2Gi"` は 2 GiB を表す。`"2GB"` のような単位の誤記や、最終的なリクエストが上限を超える指定は `rubectl render` が宣言の行番号とともに報告する。

`configmap(NAME)`と`secret(NAME)`は、参照先を表す値を返す。トップレベルの`secret`はSecretを宣言するメソッドなので、参照を表すのはブロックの中だけである。

ブロックが終わった時点で、次の値を補う。

- `selector`が必須の型で`selector`を書いていない場合、テンプレートのラベルを選ぶ`selector`を作る。テンプレートにラベルがなければ`app: <名前>`を使う。
- `selector`の`matchLabels`を、テンプレートのラベルに加える。
- JobとCronJobで`restartPolicy`を書いていない場合、`Never`にする。APIが受け付ける既定値がないためである。

これらのメソッドが書くのは通常のフィールドである。生成されたフィールドメソッドと同じブロックで併用できる。短い書き方が用意していないフィールドは、フィールドメソッドで書く。

## StatefulSet のレプリカごとに PVC を作る

```ruby
stateful_set "db" do
  service_name "db"
  replicas 2

  data = volume_claim_template "data" do
    access_modes ["ReadWriteOnce"]
    storage_class_name "fast"
    resources { requests storage: "10Gi" }
  end

  init_container("prepare", image: "busybox:1.37") { mount data, at: "/data", read_only: true }
  container "db", image: "postgres:17" do
    mount data, at: "/var/lib/postgresql/data"
  end
end
```

StatefulSet は各レプリカに `data-db-0`、`data-db-1` のような PVC を作る。PVC は StatefulSet の名前空間に属する。参照は同じ StatefulSet のコンテナで使い、テンプレート名は他のボリューム名と重複させない。`resources` のストレージ容量には Kubernetes の単位を使う。たとえば `1024Mi` は `1Gi` になる。`volume_mode "Block"` のテンプレートは `device data, at: "/dev/data"` に渡す。

`mount "data", at: "/data"` のように名前で指定する書き方も使える。テンプレートをコンテナの後や生成フィールド `volume_claim_templates` で書いた場合も、`mount` と `device` の指定を照合する。同名の Pod ボリュームがある場合、名前で指定したマウントのモード照合には Kubernetes と同じくテンプレートを使う。

## ConfigMap の変更でロールアウトする

```ruby
settings = config_map("web-config") { data LOG_LEVEL: "info" }

deployment "web" do
  rollout_on settings
  container "web", image: "nginx:1.27" do
    env "LOG_LEVEL", from: settings, key: :LOG_LEVEL
  end
end
```

Deployment、StatefulSet、DaemonSet で `rollout_on` に同じマニフェストの ConfigMap を渡すと、Pod テンプレートの `rubernetes.io/configmap-checksum` にチェックサムを記録する。複数の ConfigMap を指定できる。`data` の値や `binaryData` のバイト列が変わると、次の apply 時にテンプレートが変わり、各コントローラが構成済みの更新戦略に従う。引数やキーの並び順、ConfigMap のラベル・アノテーションだけを変えてもチェックサムは変わらない。

`env` と `volume` の `from:` には宣言した ConfigMap または Secret を渡せる。`env` の `key:` は宣言中のキーと照合し、参照元と参照先の両方に名前空間を指定した場合は一致を確認する。別ファイルやクラスタに既にあるリソースは従来通り `configmap("名前")`、`secret("名前")` で参照できる。

## 名前空間ごとに宣言をまとめる

`in_namespace "preview" do ... end` の中では、スキーマレジストリで名前空間スコープのリソースに `metadata.namespace` を補う。名前には Kubernetes の DNS ラベルを使う。ネストしたブロックから戻ると外側の名前空間に戻り、各宣言の `namespace:` を使えば既定値を上書きできる。Namespace や ClusterRole などのクラスタスコープのリソースには名前空間を補わない。`expose`、`autoscale`、`disruption_budget` はブロックの外から呼び出しても、参照するワークロードの名前空間でリソースを宣言する。

## ワークロードから Service を作る

`autoscale web, replicas: 2..8, cpu: 70, memory: 80` は、宣言済みワークロードの名前・種類・API バージョンを参照する標準の autoscaling/v2 HorizontalPodAutoscaler を同じ名前空間に生成する。`name:` で HPA の名前を指定できる。対象は生成スキーマに更新可能な scale サブリソースがあるリソース。レプリカ数は有限の整数 Range で指定し、`2...8` の上限は 7 になる。CPU とメモリの片方または両方のリクエストに対する平均使用率を指定する。

`container:` に宣言したコンテナ名を文字列またはシンボルで渡すと、各指標を autoscaling/v2 の ContainerResource として生成する。Pod テンプレートの通常コンテナと再起動可能なサイドカーを指定できる。

`web = deployment "web" do ... end` の戻り値を `expose web, ports: {http: 80, metrics: 9090}` に渡すと、ワークロードと同じ名前・名前空間に Service を宣言する。Service の各ポートは、コンテナに宣言した同名の `targetPort` とそのプロトコルを使う。`name:` と `type:` で Service 名と種別を指定できる。既定の種別は ClusterIP。`:cluster_ip`、`:node_port`、`:load_balancer` も種別として使える。LoadBalancer には `load_balancer_class:` と `allocate_node_ports:` を指定できる。

Pod はそのラベル、Deployment・StatefulSet・DaemonSet・ReplicaSet は `spec.selector` を使う。ReplicationController は `spec.selector` を使う。省略した場合は Kubernetes の既定値に従い、Pod テンプレートのラベルで選択する。`matchExpressions` は、各キーで許可される値が一つに決まる場合に Service のラベルへ変換する。たとえば `track In [stable, canary]` と `track NotIn [canary]` は `track: stable` になる。該当する値が複数残る場合や、キーの存在・不在だけを指定した場合は、評価時にエラーになる。通常のコンテナと再起動可能なサイドカーが公開するポートを参照できる。未宣言・重複したポート名を参照すると、マニフェストの該当行で評価が失敗する。

## ワークロードに PodDisruptionBudget を設定する

```ruby
web = deployment "web", namespace: "production" do
  replicas 3
  container "web", image: "nginx:1.27"
end

disruption_budget web, max_unavailable: 1
```

Deployment、ReplicaSet、StatefulSet、ReplicationController の宣言を渡すと、同じ名前空間に標準の `policy/v1` PodDisruptionBudget を生成する。既定ではワークロードと同じ名前を使い、`name:` で変更できる。`max_unavailable:` と `min_available:` の片方に、0から2147483647までの整数、または `"25%"` のような0%から100%までの文字列を指定する。

ワークロードの `matchLabels` と `matchExpressions` をそのまま使う。ReplicationController でセレクターを省いた場合は Kubernetes の既定値に従い、Pod テンプレートのラベルを使う。空のセレクターや、ワークロードの Pod に一致しないセレクターは評価時にエラーになる。

## apply の変更を確認する

`rubectl plan -f app.rb --allow-code` は、各オブジェクトの現在値を取得し、同じ field manager と `--force` の設定で server-side apply の `dryRun=All` を実行する。`action` は `create`、`update`、`unchanged` のいずれかになる。更新するフィールドは JSON Pointer の `changedPaths` で示す。値は出力しない。API の拒否やフィールド所有権の競合はコマンドのエラーになる。 `-o text` は各宣言のアクション、種類・名前空間・名前、ファイル名と Ruby の宣言行を表示し、変更パスを次の行に並べる。標準入力の場合は `<stdin>` と表示する。

各宣言は現在のクラスタに対して個別に評価する。新しい Namespace や CRD に依存するリソースを plan するには、その Namespace や CRD がすでに必要になる。

## 出力の確認

`rubectl render -f app.rb --allow-code` は、`apply` が送るオブジェクトを標準出力に書く。単一リソースの JSON はそのオブジェクト、複数なら宣言順の `v1/List` になる。`-o yaml` ではリソースごとに YAML ドキュメントを出力する。どちらも `kubectl apply -f -` や `rubectl plan -f -` に渡せる。`--env` で渡した値も出力に含まれる。

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
