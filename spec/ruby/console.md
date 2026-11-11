[仕様書の目次](../README.md) / [Ruby設計](README.md)

<a id="sec-3-7"></a>
# 3.7 コンソール

> 対象読者: クラスタ管理者、Ruby実装者、審査者
>
> 状態: 規範、版0.1

動いているコンポーネントの中を、止めずに調べる手段を定義する。対象は、プロセスが持つオブジェクト、スケジューラの判断、メソッドの呼び出しの3つである。

## 位置づけ

Kubernetesのコンポーネントの内部を調べる手段は、ログ、メトリクス、プロファイラである。知りたいことがログに出ていなければ、verbosityを上げて再起動するか、デバッガを接続する。

Rubyのプロセスは、実行中に自分のオブジェクトを調べられる。メソッドの呼び出しをあとから観測することもできる。コンソールはこの性質を、クラスタの運用の道具として公開する。

| 知りたいこと | Kubernetesでの方法 | Rubernetesでの方法 |
|---|---|---|
| コンポーネントがいま持っている状態 | ログとメトリクスから推測する | `rubectl console`でオブジェクトを直接見る |
| Podがそのノードに置かれた理由、置かれない理由 | kube-schedulerを`-v=10`で動かし、次の試行のログを読む | `rubectl why`で直近の判断を表示する |
| あるメソッドが呼ばれた時刻、引数、所要時間 | ログを足して再ビルドする | `rubectl trace`で実行中に観測する |

## ソケット

コンポーネントは、設定のトップレベルに`console.socket`があるときだけ、そのパスのUnixソケットで待ち受ける。既定では待ち受けない。

```yaml
console:
  socket: /var/lib/rubernetes/clusters/default/run/scheduler.sock
```

接続した利用者は、プロセスが持つすべてを読み書きできる。そのため、接続できる利用者を次のとおり限定する。

- ソケットのモードは0600、置き場所のディレクトリは0700とする。
- 接続元のuidが、rootかコンポーネントの実行ユーザーでない場合は切断する。

この2者は、もともとそのプロセスにデバッガを接続できる利用者である。コンソールは新しい権限を与えない。

ソケットを開けなかった場合は、ログに記録してコンポーネントの起動を続ける。パスが100バイトを超える場合は開かない。

`rubectl cluster up`は、クラスタのすべてのプロセスに`<クラスタのディレクトリ>/run/<プロセス名>.sock`を設定する。

## プロトコル

要求と応答は、1行に1つのJSONオブジェクトとする。

| 要求 | 応答 |
|---|---|
| `{"op":"hello"}` | `process`、`pid`、`ruby` |
| `{"op":"eval","code":"..."}` | `result`と`output`、または`error`と`output` |
| `{"op":"trace","target":"...","seconds":N,"limit":N}` | 呼び出しごとに`call`。最後に`done`と`calls`、または`error` |

## 評価

`eval`のコードは、セッションごとに1つのbindingで評価する。プロンプトで代入したローカル変数は、セッションの間残る。

`self`は、コンポーネントごとのコンテキストである。コンテキストのメソッドが、プロンプトから呼べる道具になる。`help`が一覧を表示する。

| コンポーネント | 道具 |
|---|---|
| すべて | `service`、`ivars(object)`、`ivar(object, :name)`、`threads`、`memory`、`help` |
| `rubernetes-scheduler` | `framework`、`queue`、`plugins`、`nodes`、`pods`、`decisions`、`why(pod)` |
| `rubernetes-apiserver` | `server`、`store`、`raft`、`admission`、`keys(prefix)` |
| `rubernetes-controller-manager` | `manager`、`leader?`、`controllers` |
| `rubernetes-agent` | `agent`、`lifecycle`、`pods` |
| `rubernetes-proxy` | `proxy` |

評価の上限は30秒とする。例外は、`SyntaxError`と`SystemExit`を含めてセッションに報告し、コンポーネントには伝えない。

プロンプトでの`exit`、`exit!`、`abort`は、コンポーネントを止めずに例外にする。セッションは接続を閉じて終える。

プロンプトでの`puts`、`print`、`p`の出力は、コンポーネントのログではなくセッションに返す。

### 値の表示

コンポーネントのオブジェクトは、互いにクラスタ全体を保持している。Rubyの`inspect`をそのまま使うと、出力が数メガバイトになる。そこで次のように表示する。

- 数値、シンボル、文字列、配列、ハッシュ、Struct、Dataは、データとして表示する。配列とハッシュは20要素まで、文字列は400文字まで、入れ子は3段までとする。
- それ以外のオブジェクトは、クラス名とインスタンス変数の名前だけを表示する。中身は`ivar`で1段ずつたどる。

## スケジューラの判断

`rubernetes-scheduler`は、試行したPodごとに、最後の判断を記録する。記録するのは直近の512個のPodである。プロセスを再起動すると記録は消える。

1つの判断は次のものを持つ。

- 結果、選んだノード、試行回数、所要時間、時刻
- Filterで外れたノードごとに、外したプラグインの名前と理由
- 残ったノードごとに、合計点と、プラグインごとの点数とweight。点数の高い順に20ノードまで

`rubectl why [NAMESPACE/]POD`は、この記録を表示する。namespaceを省略した場合は`default`とする。

```text
default/crunch: scheduled on worker-2  (attempt 1, 29.71 ms, 2026-11-11T15:34:20.272Z)
  worker-2    599  TaintToleration 100x3  NodeResourcesFit 99  team-rules.PreferQuietNodes 100x2
  worker-1    579  TaintToleration 100x3  NodeResourcesFit 99  team-rules.PreferQuietNodes 90x2
  worker-0      -  team-rules.KeepBatchOffInteractive: node is reserved for interactive workloads
```

点数が0のプラグインは表示しない。[Extension](extensions.md)のプラグインは、組み込みのプラグインと同じ形式で現れる。

## 呼び出しの観測

`trace`は、指定したメソッド1つにだけTracePointを取り付ける。観測している間、ほかのメソッドの実行には影響しない。観測を終えると取り外す。

対象は`Some::Class#method`か`Some::Module.method`の形式で指定する。存在しないメソッドは、取り付ける前に失敗させる。

呼び出しが戻るたびに、次のものを報告する。

- 時刻
- 所要時間。単位はミリ秒
- 引数。位置引数とキーワード引数を、名前付きで示す
- 戻り値
- スレッド名

`rubectl trace`は、このうち時刻、所要時間、引数、戻り値を1行で表示する。

引数と戻り値は短い形で表示する。Kubernetesのオブジェクトは種類と名前、配列とハッシュは要素数、それ以外はクラス名とする。

観測は、指定した秒数が過ぎるか、指定した回数を報告した時点で終える。上限は600秒、10,000回とする。既定は10秒、200回である。

同じメソッドが複数のスレッドで動いている場合と、再帰している場合も、呼び出しと戻りを正しく対応させる。

## rubectl

| コマンド | 動作 |
|---|---|
| `rubectl console PROCESS` | 対話のプロンプトを開く。標準入力が端末でない場合は、入力を1行ずつ評価する |
| `rubectl console PROCESS -e CODE` | 1つの式を評価して終える。例外の場合は終了コードを1にする |
| `rubectl why [NAMESPACE/]POD` | スケジューラの判断を表示する |
| `rubectl trace PROCESS TARGET [--seconds N] [--limit N]` | 呼び出しを観測する |

`PROCESS`は、`cluster.json`のプロセス名である。一意に決まる先頭部分だけを書いてもよい。クラスタは`--name`か`--root`で選ぶ。

対話のプロンプトは、入力が途中かどうかを構文解析で判定する。閉じていない`do`、括弧、文字列がある間は、続きの行を待つ。それ以外の構文エラーは、その場で報告する。

## 関連

- [Extension](extensions.md)
- [スケジューラ](../control-plane/scheduler.md)
- [検証戦略](../verification/testing.md)
