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

Rubyで書いたマニフェストを読み込むには`--allow-code`が必要です。マニフェストは隔離したサンドボックスの中で評価されます。

実装していない機能を呼ぶと、エラーで終了します。成功したように見せることはありません。

## 実行例

```sh
ruby -Ilib exe/rubernetes-apiserver --config /etc/rubernetes/apiserver.yml --check-config
ruby -Ilib exe/rubectl --kubeconfig ~/.kube/config get pods -n kube-system -o yaml
```

## 関連

- [命名](../spec/foundation/naming.md)
- [Project structure](../spec/delivery/project-structure.md)
- [マイルストーン](../spec/delivery/milestones.md)
