# Rubyで書くマニフェストの例

[English](README.md) | 日本語

マニフェストをRubyで書く例です。出力は標準のKubernetesオブジェクトなので、本物の`kubectl`にそのまま渡せます。規則は[仕様](../../spec/ruby/manifest-dsl.md)にあります。

| ファイル | 内容 |
|---|---|
| [web.rb](web.rb) | ConfigMap、Deployment、Service。本番では CPU 使用率 70% を目標に 3〜8 レプリカで自動スケールする |
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
    port 80, name: :http
    cpu request: "100m", limit: "500m"
    env from: configmap("web-config")
    http_probe :readiness, port: :http, period_seconds: 5
  end
end
```

フィールドはスキーマと照合されます。書き間違いは、適用する前に、行番号と候補つきで分かります。

```text
web.rb:9: containers.nginx.readinessProbe.httpGet: HTTPGetAction has no field "pathh" (did you mean "path"?)
web.rb:2: Deployment has no field or helper "replica" (did you mean "replicas"?)
```

繰り返しや条件分岐、共通部分のメソッド化には、Rubyをそのまま使います。テンプレート言語は要りません。[tenants.rb](tenants.rb)がその例です。

## ヘルパー

ワークロードのブロックで使える短い書き方の一覧です。

`check`に渡したRubyのブロックは、そのファイルの宣言がそろってから、クラスタに接続する前に実行されます。たとえば本番環境のDeploymentにチーム名を必須にできます。条件が偽なら`render`、`plan`、`apply`は宣言行と理由を表示して終了します。

```ruby
check "本番の Deployment に team ラベルが必要" do |resources|
  resources.select { |r| r["kind"] == "Deployment" && r.dig("metadata", "namespace") == "prod" }
           .all? { |r| !r.dig("metadata", "labels", "team").to_s.empty? }
end
```

`http_probe`の`port: :http`は、同じコンテナに宣言したTCPポートを指します。名前を間違えると`rubectl render`がRubyの行番号と使える名前を表示します。ポートを後の行に宣言しても解決できます。

Podのラベルは`env_field "TEAM", label: "example.com/team"`、注釈は`env_field "REVISION", annotation: "example.com/revision"`で環境変数として渡せます。値はコンテナの起動時に決まります。

`env_resource "CPU_MILLICORES", "requests.cpu", divisor: "1m"`では、このコンテナのCPU要求をミリコア単位で環境変数に設定します。`container: "worker"`を追加すると、同じPodの通常コンテナ、initコンテナ、サイドカーを参照できます。後から宣言したコンテナも参照できます。`divisor`を省略するとKubernetesの既定値`1`が使われます。

仮想ホストで応答するアプリは`http_probe :readiness, port: :http, path: "/ready", headers: {Host: "catalog.example.test"}`と書けます。接続先はPodのまま、指定したHostで確認します。同名のヘッダーを複数送る場合は値を配列で渡せます。

データベースの起動待ちには`tcp_probe :startup, port: :sql`、gRPCのサービスには`grpc_probe :readiness, port: 9000, service: "catalog"`を使えます。コンテナ内でコマンドを実行する場合は`exec_probe :liveness, command: ["pg_isready", "-q"]`のように引数を配列で渡します。

`settings`のデータを変えて再適用すると、Deploymentが新しい環境変数を持つPodに順次置き換えます。ConfigMapのラベルだけを編集した場合は稼働中のPodを維持します。`env from: settings`にはRubyの宣言をそのまま渡せます。

コンテナ内で`mount settings, at: "/etc/app"`と書くと、ConfigMapをファイルとして読み取れます。Podのボリュームと読み取り専用マウントを生成し、複数のコンテナで同じボリュームを共有できます。Secretも同じ書き方で参照できます。`mount "cfg", from: settings, at: "/etc/app"`ではボリューム名を指定できます。PersistentVolumeClaimの宣言も同じように渡せます。`mount uploads, at: "/data"`で書き込み、読み取り専用のコンテナには`read_only: true`を付けます。ブロックモードのPVCには`device disk, at: "/dev/data"`を使います。

複数の設定を同じディレクトリに置くには`mount "cfg", from: [defaults, overrides], at: "/etc/app"`と書きます。同名のファイルには配列の後ろの内容が反映されます。

StatefulSetでは`data = volume_claim_template "data" do ... end`でレプリカごとのPVCを宣言できます。ブロックに`access_modes ["ReadWriteOnce"]`や`resources { requests storage: "10Gi" }`を書き、初期化コンテナやアプリで`mount data, at: "/data"`と宣言を参照できます。`volume_mode "Block"`を指定した場合は`device data, at: "/dev/data"`を使います。

`empty_dir`の戻り値をRubyの変数に入れると、初期化コンテナとアプリで同じボリュームを共有できます。既定はディスクで、`medium: :memory`でtmpfsを選べます。`size_limit:`はボリューム単位の上限です。

```ruby
pod "report" do
  restart_policy "Never"
  cache = empty_dir "cache", medium: :memory, size_limit: "32Mi"
  init_container("prepare", image: "busybox:1.36") do
    mount cache, at: "/out"
    command ["sh", "-c", "echo ready > /out/status"]
  end
  container("reader", image: "busybox:1.36") do
    mount cache, at: "/input", read_only: true
    command ["cat", "/input/status"]
  end
end
```

`in_namespace "preview" do ... end`で環境ごとの宣言をまとめられます。ブロック内の名前空間スコープのリソースには`preview`が補われ、各宣言の`namespace:`で上書きできます。ネストしたブロックを抜けると、外側の名前空間に戻ります。NamespaceやClusterRoleなど、クラスタスコープのリソースに名前空間は補われません。

```ruby
in_namespace "preview" do
  account = service_account "web"
  registry = secret "registry" do
    type "kubernetes.io/dockerconfigjson"
    string_data ".dockerconfigjson" => ENV.fetch("DOCKER_CONFIG_JSON")
  end

  deployment "web" do
    use_service_account account
    image_pull_secrets registry
    container "app", image: "registry.example.test/web:1"
  end
end
```

このファイルをrubectlで評価するときは`--env DOCKER_CONFIG_JSON`を付けます。ヘルパーはPod、Deployment、Job、CronJobなどのPodSpecに`serviceAccountName`と`imagePullSecrets`を設定します。宣言した参照先はワークロードと同じ名前空間に置きます。PodSpecに`image_pull_secrets [{name: "existing"}]`で一覧を指定している場合、Secret名の重複を除いて追記します。クラスタにすでにあるSecretは`image_pull_secrets secret("existing")`で参照できます。

`expose web, ports: {http: 80}`は、Deploymentの名前空間とセレクタを引き継ぎ、コンテナの名前付きポート`http`を公開するServiceを生成します。`prefer: :same_zone`または`prefer: :same_node`を加えると、Serviceの`trafficDistribution`で同じゾーンまたはノードのエンドポイントを優先します。ポート名や優先設定を書き間違えると、`render`と`apply`はクラスタへの送信前にRubyの行番号と指定できる名前を表示します。

`ingress_for`は、`service`や`expose`で宣言したServiceと同じ名前・名前空間に`networking.k8s.io/v1`のIngressを生成します。ServiceのポートがTCPの1つだけなら`port:`を省略できます。複数ある場合は、`:http`や`80`のようにTCPのServiceポートを名前または番号で指定します。既定は`path: "/"`と`path_type: :prefix`です。完全一致には`path_type: :exact`、IngressClassの選択には`class_name:`を使います。通信の処理はクラスタのIngressコントローラーが行います。

`sidecar("proxy", image: "proxy:1") { port 8443, name: "https" }`はKubernetesの再起動可能なサイドカーを宣言します。後続の初期化コンテナより先にプロキシが起動し、`expose web, ports: {https: 443}`からそのポートを参照できます。

ワークロードのブロックに`spread_across "topology.kubernetes.io/zone"`と書くと、ゾーン間のPod数の差を最大1に抑えます。後から書いた`matchExpressions`も含め、ワークロードのセレクターをそのまま使います。均等配置が難しいときも起動を優先するなら`when_unsatisfiable: :schedule_anyway`を指定します。

`autoscale web, replicas: 2..8, cpu: 70`と書くと、同じ名前空間にHorizontalPodAutoscalerを生成します。CPU使用率がリクエストの70%になるように、2〜8レプリカの範囲で調整します。HPAに台数を任せるときはDeploymentの`replicas`を省き、コンテナにCPUリクエストを設定します。稼働中の調整にはリソースメトリクスAPIが必要です。

プロキシのサイドカーを持つDeploymentで、アプリの負荷を基準に台数を変えたいときは、`autoscale web, replicas: 2..8, cpu: 70, container: :api`と書けます。CPUやメモリの使用率を指定コンテナだけで計算します。

RBS対応エディタにgemの`sig/`を読み込むと、宣言やヘルパーのメソッド名を補完し、キーワード引数と型を参照できます。`:api`のようにマニフェスト内で宣言した名前は評価時に解決されます。コンテナ名を書き間違えるとRubyの行番号と指定できる名前を表示します。

Rubyマニフェストのトップレベルと`in_namespace`のブロックでは、`self`は`Rubernetes::Manifest::Builder`です。`resource`のブロックでは`Rubernetes::Manifest::ObjectBuilder`になります。SteepではRubyのブロック内でレシーバーの型を指定します。この例の`tap`では、マニフェストのレシーバーをそのまま使えます。

```ruby
tap do
  # @type self: Rubernetes::Manifest::Builder
  web = deployment :web, namespace: :preview do
    container :api, image: "nginx:1.27" do
      port 80, name: "http"
      cpu request: "100m"
    end
  end

  frontend = expose web, ports: {http: 80}
  ingress_for frontend, host: "web.example.test", port: :http
  autoscale web, replicas: 2..8, cpu: 70, container: :api
  disruption_budget web, max_unavailable: "25%"
end
```
