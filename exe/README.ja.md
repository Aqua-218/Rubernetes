# 実行ファイル境界

[English](README.md) | 日本語

`rubectl`、`rubernetes-apiserver`、`rubernetes-controller-manager`、
`rubernetes-scheduler`、`rubernetes-agent`、`rubernetes-proxy` がここにあります。
実行ファイルはプロセスレベルのオプションを解釈して `Rubernetes::Bootstrap` に
委譲するだけで、ドメインのポリシーは `lib/rubernetes/` にあります。

すべてのデーモンは `--help`、`--version`、`--config PATH`、`--check-config` を
実装します。help と version の経路では設定を読まず依存も組み立てません。
デーモンは YAML 1 ファイルだけを読み（環境変数は読まない）、依存が組み上がり
健全になって初めて ready になり、`SIGINT`/`SIGTERM` で正常停止します。
`rubectl` は kubeconfig または明示的な `--server` / 認証フラグに対して `get`、
`create`、`apply`、`patch`、`delete`、`watch`、`raw` を提供し、Ruby マニフェストは
隔離サンドボックス内でのみ読み込みます（`--allow-code`）。未実装のものは偽の
成功ではなくエラーで失敗します。

```sh
ruby -Ilib exe/rubernetes-apiserver --config /etc/rubernetes/apiserver.yml --check-config
ruby -Ilib exe/rubectl --kubeconfig ~/.kube/config get pods -n kube-system -o yaml
```

## 関連

- [命名](../spec/foundation/naming.md)
- [Project structure](../spec/delivery/project-structure.md)
- [マイルストーン](../spec/delivery/milestones.md)
