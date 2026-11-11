# Extensionの例

[English](README.md) | 日本語

Rubyファイル1枚でクラスタの振る舞いを書き足す例です。仕組みと規則は[仕様](../../spec/ruby/extensions.md)にあります。

| ファイル | 足すもの | 動作 |
|---|---|---|
| [team_rules.rb](team_rules.rb) | `validate`、`filter`、`score` | Podに`team`ラベルを必須にする。`tier: batch`のPodを`workload: interactive`のノードに置かない。空いているノードを少し優先する |
| [restart_on_config_change.rb](restart_on_config_change.rb) | `controller` | ConfigMapが変わったら、それを読んでいるDeploymentをロールアウトし直す |
| [namespace_defaults.rb](namespace_defaults.rb) | `controller`、`validate` | 新しいnamespaceにLimitRangeとResourceQuotaを作る。その2つの削除を拒否する |

## 試し方

Extensionを有効にしたクラスタを作ります。

```sh
sudo ruby -Ilib exe/rubectl cluster up --workers 3 --extensions
export KUBECONFIG=/var/lib/rubernetes/clusters/default/kubeconfig
```

ファイルを手元で確かめ、適用します。`check`はクラスタに何も送りません。

```sh
ruby -Ilib exe/rubectl extension check examples/extensions/*.rb
ruby -Ilib exe/rubectl extension apply examples/extensions/restart_on_config_change.rb
```

ConfigMapを読むDeploymentを作り、ConfigMapだけを変えます。

```sh
kubectl create configmap site --from-literal=MESSAGE=hello
kubectl create deployment site --image=busybox:1.36 -- sh -c 'echo $MESSAGE; sleep 3600'
kubectl set env deployment/site --from=configmap/site
kubectl rollout status deployment/site

kubectl patch configmap site --type merge -p '{"data":{"MESSAGE":"changed"}}'
kubectl rollout status deployment/site    # Deploymentには触れていないのにロールアウトが走る
kubectl logs -l app=site --prefix          # 新しいPodがchangedを出力する。古いPodは終了待ちで、しばらく残る
```

状態の確認と削除は次のとおりです。

```sh
ruby -Ilib exe/rubectl extension list
ruby -Ilib exe/rubectl extension delete restart-on-config-change
```

## 書くときの注意

- ブロックはコンポーネントのプロセスの中で動きます。重い処理や、終わらない処理を書かないでください。呼び出しには時間の上限があります。
- `filter`と`score`は、Podごと、ノードごとに呼ばれます。APIを呼ぶ処理は`controller`に書いてください。
- `validate`や`mutate`のブロックが例外を出すと、その要求は拒否されます。`"*"`を対象にするときは特に注意してください。Extension自身の削除は必ず通ります。
- トップレベルの`def`と定数は、同じファイルのブロックからだけ見えます。
