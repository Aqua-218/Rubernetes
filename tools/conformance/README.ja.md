# Conformanceツール

[English](README.md) | 日本語

Kubernetesとの互換性を検査するためのRubyコマンド群です。次の作業を受け持ちます。

- 固定したupstreamの入力を検証する。
- リリースと同じ構成のクラスタを起動する。
- 固定したHydrophoneとSonobuoy、それにupstreamの`e2e.test`を実行する。
- JUnitとGinkgoの出力を正規化する。
- upstreamのe2e一覧を分類する。
- M8の証拠マニフェストを出力する。

ツールはupstreamの実行ファイルを呼び出すだけです。upstreamのソース、focus式、skip式、実行結果を改変してはいけません。upstreamの実行が失敗したり途中で終わったりした場合は、そのまま失敗として扱います。

## コマンド一覧

| コマンド | 役割 |
|---|---|
| `lock.rb` | `third_party/locks/`を読み出す。Kubernetesのコミット、Conformanceイメージのダイジェスト、ランナーの成果物を返す |
| `install_tools.rb` | HydrophoneとSonobuoyを`build/conformance/bin`に入れる。アーカイブはロックと照合する。`rake m8:tools`で実行 |
| `build_e2e.rb` | 固定したチェックアウトからupstreamの`e2e.test`をビルドする。`rake m8:e2e_build`で実行 |
| `cluster.rb up\|down\|status` | control 3ノードとworker 3ノードのクラスタを`--root`配下に起動、停止する。本物の`exe/rubernetes-*`を使い、PKI、kubeconfig、クラスタDNSも用意する |
| `netns_env.sh up\|down\|exec` | クラスタごとにネットワーク名前空間を用意する。uplink、NAT、リゾルバが付く |
| `round.sh` | 名前空間の中でHydrophoneのConformanceを1ラウンド実行する。JUnitの合計と失敗したspec名を出力する |
| `run.rb` | K1〜K7の検査を実行し、プロファイルごとの実行マニフェストを書く。`rake m8:lanes`で実行 |
| `build_selection_ledger.rb` | Ginkgoのdry-runからK3の選択台帳を再生成する。`rake m8:selection_ledger`で実行 |
| `resolve_image_digests.rb` | コーパスが使うイメージのタグを、ロック用のダイジェストに解決する |

検査の実装は`k0_input_integrity.rb`、`k5_differential.rb`、`k6_corpus.rb`、`k7_lifecycle.rb`、`lanes.rb`にあります。

## 日常の実行手順

```bash
export PATH=/opt/rubies/3.4.11/bin:$PATH
rake m8:tools                                               # hydrophoneとsonobuoyを導入。1回だけ
tools/conformance/netns_env.sh up conf4 --v4 3 --v6 e7      # クラスタごとに名前空間を1つ作る
RUBERNETES_M8_CGROUP_ROOT=/sys/fs/cgroup/conf4 \
  tools/conformance/netns_env.sh exec conf4 -- \
  ruby tools/conformance/cluster.rb up --profile linux-amd64-ipv4-native --root /srv/rbn-conf4
setsid nohup tools/conformance/round.sh conf4 /srv/rbn-conf4/linux-amd64-ipv4-native \
  /srv/rbn-conf4/rounds/01 --parallel 4 > /srv/rbn-conf4/rounds/01.out 2>&1 &
```

`--parallel 4`で全件を実行すると、1台のホストで約40分かかります。

結果は`junit_01.xml`で確認してください。Hydrophoneは合格したspecについて何も出力しません。ログが止まって見えても、実行は続いています。

修正を確かめるための再実行には`--focus`を使います。`--focus`付きの実行は別の実行として扱われ、全件実行の結果を置き換えません。

このツリーで最後に全件を実行したのは2026-09-30で、IPv4プロファイルで459件中459件が合格しました。

## IPv6とdual-stackのプロファイル

`test/conformance/kubernetes/profiles.yml`に3つのプロファイルが定義してあります。どれも1台のホスト上にcontrol 3ノードとworker 3ノードを作ります。

| プロファイル | アドレス |
|---|---|
| `linux-amd64-ipv4-native` | IPv4だけ |
| `linux-amd64-ipv6-native` | IPv6だけ。Pod CIDRは`fd00:d8:<n>::/48`、service CIDRは`fd00:d8:5::/112` |
| `linux-amd64-dualstack-native` | 両方。プロファイルで先に書いてあるIPv4がprimaryになる |

残りの設定は`cluster.rb`がプロファイルから決めます。

- プロファイルにIPv6があれば、APIサーバは`::`にbindします。advertiseするのはprimaryファミリのアドレスです。
- `kubernetes` Serviceとそのendpointsもprimaryファミリに従います。
- 各ノードはファミリごとに1つの`InternalIP`を公開します。値はPodブリッジの先頭アドレスで、`10.24n.0.1`と`fd00:d8:n::1`です。
- サービング証明書には両ファミリのアドレスが入ります。

クラスタはそれぞれ専用のネットワーク名前空間で動きます。そのため、Podブリッジ、nftablesのテーブル、NodePort、経路がホストやほかのクラスタと衝突しません。

```bash
export PATH=/opt/rubies/3.4.11/bin:$PATH            # Gemfileが指定するRuby
export RUBERNETES_M8_CGROUP_ROOT=/sys/fs/cgroup/lanes   # クラスタごとにcgroup rootを1つ
tools/conformance/netns_env.sh up lanes6 --v4 1 --v6 e6   # veth uplink、NAT、resolv.confを用意
tools/conformance/netns_env.sh exec lanes6 -- \
  ruby tools/conformance/cluster.rb up --profile linux-amd64-ipv6-native --root /srv/rbn-lanes
tools/conformance/round.sh lanes6 /srv/rbn-lanes/linux-amd64-ipv6-native \
  /srv/rbn-lanes/rounds/ipv6-01 --parallel 4          # setsid nohupで起動する
```

### netns_env.sh

`netns_env.sh up <name> --v4 <n> --v6 <hex>`は次の設定を行います。

- 名前空間にホストへのuplinkを作る。アドレスは`10.250.<n>.0/30`と`fd00:1a:<hex>::/64`。
- 名前空間の中で、Podのトラフィックをuplinkのアドレスにマスカレードする。
- ホスト側で、uplinkからの通信を外向きにマスカレードし、転送を有効にする。
- `/etc/netns/<name>/resolv.conf`を書く。ホストのスタブリゾルバ`127.0.0.53`には名前空間の中から届かないためです。

`exec`はcgroup2を`/sys/fs/cgroup`にマウントし直します。`ip netns exec`が新しいsysfsをマウントし、その結果cgroup2が見えなくなるためです。

2つ目のクラスタを作るときは、別の`<n>`と`<hex>`、別の`RUBERNETES_M8_CGROUP_ROOT`を指定してください。`cluster.rb up`が古いワークロードを消す範囲は、指定したcgroup rootの中だけです。rootを分けておけば、クラスタ同士が相手のPodを消すことはありません。

`cluster.rb up`は、同じ`--root`で動いているクラスタがあれば先に止めます。エージェントのストリーミングポートがworkerごとに固定されているためです。

### round.sh

`round.sh`は、`lock.rb`が返す固定イメージを使い、名前空間の中でHydrophoneを実行します。Hydrophoneの標準出力は末尾だけを残します。終了後、`junit_01.xml`から合計と失敗したspec名を取り出して出力します。合否はJUnitで判断し、Hydrophoneの標準出力では判断しないでください。

実行中の進み具合は次のコマンドで見られます。

```bash
kubectl -n conformance logs e2e-conformance-test -c conformance-container
```

### run.rb

`run.rb`は、環境変数`RUBERNETES_M8_NETNS=<name>`が設定されていれば、その名前空間の中で動きます。ランナーのコマンドも、kubeconfigの到達性の確認も、すべて`ip netns exec <name>`の下で実行されます。

### ホストからクラスタへの接続

ホストからはuplinkのアドレスでクラスタに届きます。URLは`https://10.250.<n>.2:<port>`で、ポートは`cluster.json`に書いてあります。

開発ホストのシェルでは、`http_proxy`がループバック以外のすべての宛先に適用されます。`NO_PROXY=10.250.<n>.2`を設定するか、`curl --noproxy '*'`を使ってください。設定しないと、要求がプロキシに送られて失敗します。

### プロファイルごとの違い

2026-09-27時点でわかっている違いです。

IPv6専用のプロファイルにはNAT64がありません。そのためIPv6専用のPodからIPv4の宛先には届きません。イメージの取得はノードエージェントが行い、エージェントはuplinkで両ファミリを使えます。影響を受けるのは、IPv4のインターネットに接続するテストPodだけです。

dual-stackのプロファイルでは、`kubernetes` ServiceはprimaryファミリのSingleStackになります。これはkube-apiserverが作るServiceと同じです。ノードエージェントは両ファミリの`InternalIP`を公開します。一方、Podに渡すクラスタDNSの`nameserver`は、primaryファミリのブリッジアドレスだけです。kubeletの`clusterDNS`は明示したリストですが、Rubernetesはノードのゲートウェイアドレスをプロファイルの順に使います。

すべてのプロファイルに共通の違いもあります。APIサーバの`kubernetes` Endpointsは、同じuplinkアドレスの異なるポートを、APIサーバごとに1件ずつ並べます。1台のホストに3つのレプリカがあるためです。kubeadmで作ったクラスタでは、異なるアドレスが並びます。

## 関連

- [Kubernetes 互換性試験契約](../../spec/verification/kubernetes-compatibility.md)
- [マイルストーン証拠規則](../../spec/delivery/milestones.md)
- [固定したランナー入力](../../third_party/locks/conformance-runners.json)
