# 実行ファイル

[English](README.md) | 日本語

このディレクトリには6つの実行ファイルがあります。

- `rubectl`
- `rubernetes-apiserver`
- `rubernetes-controller-manager`
- `rubernetes-scheduler`
- `rubernetes-agent`
- `rubernetes-proxy`

実行ファイルの仕事は、オプションを解釈して`Rubernetes::Bootstrap`に渡すことだけです。機能の実装は`lib/rubernetes/`にあります。

## デーモン

`rubectl`以外の5つはデーモンです。どのデーモンも`--help`、`--version`、`--config PATH`、`--check-config`を受け付けます。

- `--help`と`--version`は、設定を読まず、依存するコンポーネントも組み立てずに終了します。
- 設定は`--config`で渡したYAMLファイル1つだけから読みます。環境変数は読みません。
- 依存するコンポーネントがすべて組み上がり、正常に動いてからreadyになります。
- `SIGINT`か`SIGTERM`を受けると正常に停止します。

## rubectl

`get`、`create`、`apply`、`patch`、`delete`、`watch`、`raw`が使えます。接続先はkubeconfigか、`--server`と認証用のフラグで指定してください。

`rubectl cluster up`は、このホストの上にクラスタを1つ作ります。`start`、`down`、`status`、`kubeconfig`も使えます。root権限が必要です。オプションは`rubectl cluster --help`で確認できます。

`rubectl extension`は、Rubyで書いた拡張を適用、確認、一覧、削除します。`rubectl console`、`rubectl why`、`rubectl trace`は、このホストで動いているクラスタのプロセスの中を調べます。

Rubyで書いたマニフェストを読み込むには`--allow-code`が必要です。マニフェストは隔離したサンドボックスの中で評価されます。`rubectl render`は、マニフェストが宣言するオブジェクトを、クラスタに接続せずに出力します。

実装していない機能を呼ぶと、エラーで終了します。成功したように見せることはありません。

## rubectl logs

`rubectl logs web-0 -n production -c app --tail 100 -f`でコンテナのログを追従できます。`-p`で前回のコンテナ、`--timestamps`でログのタイムスタンプを表示します。取得範囲は`--since 10m`または`--since-time 2026-11-20T10:00:00Z`で指定できます。`-c`を省略すると、Podの`kubectl.kubernetes.io/default-container`アノテーションか、最初のコンテナを選びます。接続には現在のkubeconfigを使い、`pods`と`pods/log`の`get`権限が必要です。

## rubectl disk

`rubectl disk web-0 -n production`は、Podの一時ストレージ使用量、コンテナごとの書き込み層とログ、ボリュームの使用量を表示します。合計はkubeletが報告した値です。内訳の行には合計に含まれる値もあります。RAMとPVCは区別して表示し、種類を判定できないボリュームは不明と表示します。

`emptyDir`に正の`sizeLimit`を指定した場合は、その上限を使用量の横にバイト単位で表示します。JSONのフィールド名は`sizeLimitBytes`です。使用量がまだ未計測でも、指定した上限を確認できます。

`-o json`を付けると、`ephemeralStorageUsedBytes`、`containers`、`volumes`にバイト数を出力します。未計測の値はJSONでは`null`、テキストでは`unknown`と表示します。`status`は計測あり（`sampled`）、未配置（`notScheduled`）、Pod UIDなし（`missingUID`）、同じUIDの計測なし（`noSample`）のいずれかです。現在のkubeconfigを使い、Podとノードの`nodes/proxy`サブリソースへの`get`権限が必要です。

`rubectl disk -n production`は、名前空間内のPodを一時ストレージ使用量の多い順に表示します。未計測のPodは末尾に並びます。クラスタ全体で容量を使っているPodを探すには`rubectl disk -A`を使います。`--node worker-1`で1ノードに絞れます。一覧ではPodの`list`権限を使い、対象ノードごとの集計を1回ずつ取得します。`-o json`では、`pods`にPodの識別情報、ノード名、状態、使用量の合計（バイト）を順に出力します。

`rubectl disk node/worker-1`は、ノードのルート、ランタイムのイメージ、コンテナの各ファイルシステムについて、使用量、空き容量、総容量をバイト単位で表示します。複数の項目が同じファイルシステムを指すことがあるため、計測値は項目ごとに表示します。指定ノードの集計を1回取得し、`nodes/proxy`への`get`権限が必要です。`-o json`では、`filesystems`内の`fs`、`imageFs`、`containerFs`にそれぞれ`usedBytes`、`availableBytes`、`capacityBytes`を出力します。未計測の値はJSONでは`null`、テキストでは`unknown`と表示します。

## 実行例

```sh
ruby -Ilib exe/rubernetes-apiserver --config /etc/rubernetes/apiserver.yml --check-config
ruby -Ilib exe/rubectl --kubeconfig ~/.kube/config get pods -n kube-system -o yaml
sudo ruby -Ilib exe/rubectl cluster up --ha
```

## 関連

- [命名](../spec/foundation/naming.md)
- [プロジェクト構成](../spec/delivery/project-structure.md)
- [マイルストーン](../spec/delivery/milestones.md)
