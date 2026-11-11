[仕様書の目次](../README.md) / [Ruby設計](README.md)

<a id="sec-3-6"></a>
# 3.6 Extension

> 対象読者: クラスタ管理者、Ruby実装者、審査者
>
> 状態: 規範、版0.1

クラスタの振る舞いをRubyファイルで書き足す仕組みを定義する。足せるのは、スケジューラのプラグイン、admissionのフック、コントローラの3種類である。

## 位置づけ

Kubernetesで同じことをするには、それぞれ別の作業が要る。

| 足したいもの | Kubernetesでの方法 | Extensionでの方法 |
|---|---|---|
| スケジューラのFilterとScore | Goでプラグインを書き、kube-schedulerを再ビルドして入れ替える | `filter`と`score`のブロック |
| admissionの検証と書き換え | webhookサーバを書き、TLS証明書とともにデプロイする。式で足りる場合はCELのポリシーを書く | `validate`と`mutate`のブロック |
| コントローラ | オペレータを書き、イメージにしてデプロイする | `controller`のブロック |

Extensionは、この3つを1枚のRubyファイルにまとめる。ファイルはAPIにオブジェクトとして保存し、動いているコンポーネントが読み込む。コンポーネントの再起動は要らない。

実行中のプロセスにコードを読み込めることは、Rubyの性質である。Extensionはその性質をクラスタの拡張点として公開する。

## オブジェクト

Extensionは`rubernetes.io/v1alpha1`の`Extension`として保存する。scopeはclusterである。短縮名は`rext`とする。

```yaml
apiVersion: rubernetes.io/v1alpha1
kind: Extension
metadata:
  name: team-rules
spec:
  source: |
    validate "pods", on: :create do |request|
      request.reject("Pods need a team label") unless request.object.dig("metadata", "labels", "team")
    end
```

型はCustomResourceDefinitionとして登録する。組み込みのAPIの一覧はKubernetes v1.36.2と同じまま変えない。

`spec.source`の上限は262,144バイトとする。

`rubectl extension apply FILE.rb`は、ファイル名から名前を決めてこのオブジェクトを作る。`team_rules.rb`は`team-rules`になる。`kubectl apply`で直接作ってもよい。

## 有効化

Extensionを読み込むのは、設定に`extensions: {enabled: true}`を持つコンポーネントだけである。既定では読み込まない。

| コンポーネント | 読み込むもの | statusでの名前 |
|---|---|---|
| `rubernetes-apiserver` | `validate`、`mutate` | `admission` |
| `rubernetes-scheduler` | `filter`、`score` | `scheduler` |
| `rubernetes-controller-manager` | `controller` | `controller` |

`rubernetes-apiserver`は、有効なときに起動時にCustomResourceDefinitionを作る。すでにある場合は変更しない。

`rubectl cluster up --extensions`は、3つのコンポーネントすべてで有効にする。

## 信頼の境界

Extensionのソースは、コンポーネントのプロセスの中で、そのコンポーネントの権限で実行する。隔離はしない。

したがって、Extensionを作成または変更できる利用者は、制御面でコードを実行できる。この権限はcluster-adminと同等に扱う。既定のRBACでExtensionを書けるのは、すべてのリソースを書けるロールだけである。

[Manifest DSL](manifest-dsl.md)の隔離の規則は、Extensionには適用しない。Manifest DSLは利用者の手元で任意のファイルを評価するので隔離する。Extensionは管理者がクラスタに入れるコードなので、スケジューラのバイナリやwebhookを入れ替える操作と同じ信頼の水準に置く。

webhookやオペレータとの違いは、プロセスと資格情報をコンポーネントと共有する点である。Extensionの誤りは、そのコンポーネントの誤りになる。この仕様は、その影響を次の規則で限定する。

- Extensionオブジェクト自身への要求は、admissionのフックに渡さない。誤ったフックがあっても、Extensionの削除は必ず通る。
- ブロックの呼び出しには時間の上限を設ける。上限は、`filter`と`score`が1秒、`validate`と`mutate`が2秒、`controller`が30秒とする。
- ソースの読み込みは5秒で打ち切る。
- 読み込めなかったソースは実行しない。以前の版も実行しない。

最後の規則により、実行中のコードは保存されているオブジェクトと常に一致する。

## 宣言

ソースのトップレベルで、次のメソッドを呼んで宣言する。

| メソッド | ブロックの引数 | ブロックの戻り値、できること |
|---|---|---|
| `filter NAME` | `pod`、`node` | `true`で通す。`false`か理由の文字列で外す |
| `score NAME, weight: 1` | `pod`、`node` | 0〜100の整数 |
| `validate RESOURCE..., on: %i[create update]` | `request` | `request.reject(理由)`で拒否する。`request.warn(文)`で警告する |
| `mutate RESOURCE..., on: %i[create update]` | `request` | `request.object`を書き換える |
| `controller NAME, watch: RESOURCE` | `object`、`api`、`event` | `api`を通してクラスタを操作する |

名前に使えるのは、英字で始まる英数字、`_`、`-`である。

トップレベルの`def`は、同じExtensionのすべてのブロックから呼べる。ほかのExtensionからは見えない。定数も同じである。

宣言の誤りは読み込みの時点で失敗させる。名前の形式、`weight`の範囲、`on`の値、ブロックの有無が対象である。

### スケジューラ

`filter`と`score`は、[5.6.6](../control-plane/scheduler.md#sec-5-6-6)のプラグインとして登録する。引数、戻り値、失敗の扱い、トレースはその節に従う。

プラグイン名は`<Extension名>.<NAME>`とする。組み込みのプラグインを置き換えることはできない。

理由の文字列は、PodのPodScheduled条件のメッセージにそのまま現れる。

Extensionの集合が変わったとき、スケジューラはunschedulableなPodをすべて再試行する。Extensionのプラグインが1つでも登録されている間、opportunistic batchingは働かない。

### admission

フックは、組み込みのadmissionプラグインとwebhookのすべてが終わったあとに実行する。`mutate`のフックは検証の前に、`validate`のフックはほかの検証と同じ段階で実行する。

リソースの指定は、webhookの規則と同じ形式とする。

| 指定 | 対象 |
|---|---|
| `"pods"` | coreグループの`pods` |
| `"deployments.apps"` | `apps`グループの`deployments` |
| `"pods/status"` | サブリソース |
| `"*"` | すべてのリソース。サブリソースは含まない |
| `"*/*"` | すべてのリソースとサブリソース |

`request`は次のものを持つ。

- `operation`: `:create`、`:update`、`:delete`、`:connect`
- `group`、`version`、`resource`、`subresource`、`kind`、`namespace`、`name`
- `user`: 名前とグループ
- `object`、`old_object`: 要求のオブジェクトと、保存されているオブジェクト。どちらも複製である
- `dry_run?`

`validate`のフックが`request.object`を書き換えても、保存されるオブジェクトは変わらない。

フックが例外を発生させた場合、または時間の上限を超えた場合、要求は500で拒否する。webhookの`failurePolicy: Fail`と同じ扱いである。

APIサーバは、保存されているExtensionの一覧を最大1秒ごとに読み直す。変更が全レプリカに行き渡るまでの遅れは、この間隔で抑える。一覧の取得に失敗した場合は、読み込み済みのフックを使い続ける。

### コントローラ

`controller`のブロックは、`watch`で指定したリソースのオブジェクトごとに呼ぶ。

| `event` | 呼ぶとき |
|---|---|
| `:added` | 起動時にすでにあるオブジェクト、および新しく作られたオブジェクト |
| `:modified` | 変更されたとき |
| `:deleted` | 削除されたとき。ブロックが第3引数を宣言している場合だけ呼ぶ |
| `:resync` | watchをやり直したとき。すべてのオブジェクトについて呼ぶ |

`namespace:`と`selector:`で対象を絞れる。

同じオブジェクトへの呼び出しは直列にする。キューには、オブジェクトごとに最新の状態だけを置く。

ブロックが例外を発生させた場合は、指数バックオフで再試行する。間隔は1秒から始め、60秒を上限とする。

コントローラは、リーダーである`rubernetes-controller-manager`の中だけで動く。

`api`は次の操作を持つ。資格情報は`rubernetes-controller-manager`のものを使う。

| 操作 | 内容 |
|---|---|
| `get(resource, name, namespace:)` | 取得する。ない場合は`nil` |
| `list(resource, namespace:, selector:)` | 一覧を返す |
| `apply(manifest)` | server-side applyを行う。field managerは`extension-<Extension名>` |
| `create(manifest)` | 作成する |
| `patch(resource, name, changes, namespace:, subresource:)` | JSON merge patchを行う |
| `delete(resource, name, namespace:)` | 削除する。ない場合は`false` |
| `event(object, reason:, message:, type:)` | オブジェクトについてのEventを記録する |
| `log(message, **fields)` | コンポーネントのログに書く |

## status

各コンポーネントは、読み込みの結果を`status.components.<名前>`に書く。

| フィールド | 内容 |
|---|---|
| `loaded` | 読み込めたかどうか |
| `observedGeneration` | 読み込んだ`metadata.generation` |
| `provides` | 宣言の一覧。`filter:NAME`のように書く |
| `message` | 読み込めなかった理由。ソースの行番号を含む |
| `failures` | ブロックが例外を発生させた回数 |
| `lastFailure` | 最後の例外。フック名、例外クラス、メッセージ |
| `time` | 書いた時刻 |

実行時の失敗は、発生のたびに数える。statusへの書き込みは、Extensionごとに10秒に1回までとする。

statusの書き込みに失敗しても、読み込みの結果は変えない。

`rubectl extension apply`は、適用した世代について3つのコンポーネントの報告を最大5秒待ち、結果を表示する。手元で読み込めないファイルは送らない。

## 関連

- [Manifest DSL](manifest-dsl.md)
- [スケジューラ](../control-plane/scheduler.md)
- [コントローラ](../control-plane/controllers.md)
- [APIサーバ](../api/api-server.md)
