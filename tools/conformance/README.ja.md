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

`test/conformance/kubernetes/profiles.yml` は 3 つのプロファイルを定義します。
いずれも 1 ホスト上の control 3 + worker 3 です: `linux-amd64-ipv4-native`、
`linux-amd64-ipv6-native`（Pod CIDR `fd00:d8:<n>::/48`、service CIDR
`fd00:d8:5::/112`）、`linux-amd64-dualstack-native`（両方。プロファイルで先に
並ぶ IPv4 が primary）。`cluster.rb` は残りをプロファイルから導出します: IPv6 が
あれば API サーバは `::` に bind し primary ファミリのアドレスを advertise、
`kubernetes` Service とその endpoints もそのファミリに従い、各ノードは
ファミリごとに 1 つの `InternalIP`（Pod ブリッジの先頭アドレス `10.24n.0.1` /
`fd00:d8:n::1`）を公開し、サービング証明書には両ファミリのアドレスが入ります。

各クラスタインスタンスは専用のネットワーク名前空間で動くので、Pod ブリッジ、
nftables テーブル、NodePort、経路がホストや他インスタンスと干渉しません。

```bash
export PATH=/opt/rubies/3.4.11/bin:$PATH            # Gemfile の Ruby
export RUBERNETES_M8_CGROUP_ROOT=/sys/fs/cgroup/lanes   # インスタンスごとに cgroup root 1 つ
tools/conformance/netns_env.sh up lanes6 --v4 1 --v6 e6   # veth uplink、NAT、resolv.conf
tools/conformance/netns_env.sh exec lanes6 -- \
  ruby tools/conformance/cluster.rb up --profile linux-amd64-ipv6-native --root /srv/rbn-lanes
tools/conformance/round.sh lanes6 /srv/rbn-lanes/linux-amd64-ipv6-native \
  /srv/rbn-lanes/rounds/ipv6-01 --parallel 4          # setsid nohup で起動する
```

- `netns_env.sh up <name> --v4 <n> --v6 <hex>` は名前空間にホストへの uplink
  `10.250.<n>.0/30` + `fd00:1a:<hex>::/64` を与え、名前空間内では Pod トラフィックを
  uplink アドレスに、ホストでは uplink を外向きにマスカレードし、転送を有効化し、
  `/etc/netns/<name>/resolv.conf` を書きます（ホストの `127.0.0.53` スタブは中から
  届かない）。`exec` は `ip netns exec` の新しい sysfs が隠す cgroup2 を
  `/sys/fs/cgroup` に再マウントします。2 つ目のインスタンスは別の `<n>`/`<hex>` と
  別の `RUBERNETES_M8_CGROUP_ROOT` を使います。`cluster.rb up` の古いワークロード
  掃除はその root に限定されるので、インスタンス同士が互いの Pod を殺すことは
  ありません。`cluster.rb up` は同じ `--root` で動いているクラスタを先に止めます
  （エージェントのストリーミングポートは worker ごとに固定）。
- `round.sh` は `tools/conformance/lock.rb` の固定イメージで名前空間内の hydrophone
  を実行し、hydrophone の stdout は末尾だけ残し、`junit_01.xml` から JUnit の合計と
  失敗 spec 名を出力します。読むのは JUnit で、hydrophone の stdout ではありません。
  実行中の進捗: `kubectl -n conformance logs e2e-conformance-test -c conformance-container`。
- 公式ランナー（`tools/conformance/run.rb`、レーン K1〜K7）は `RUBERNETES_M8_NETNS=<name>`
  が設定されていれば名前空間に入ります。すべてのランナーコマンドと kubeconfig の
  到達性プローブが `ip netns exec <name>` 下で動きます。
- ホストからクラスタには uplink アドレス（`https://10.250.<n>.2:<port>`、ポートは
  `cluster.json`）で届きます。このシェルの `http_proxy` はループバック以外すべてに
  掛かるので、`NO_PROXY=10.250.<n>.2`（または `curl --noproxy '*'`）を付けないと
  すべての要求がプロキシの応答で「失敗」します。

### プロファイルごとの既知の差異（2026-09-27）

- IPv6 専用: IPv6 専用 Pod には IPv4 宛先への経路がありません（NAT64 なし）。
  イメージ取得は uplink 経由で両ファミリを持つノードエージェントが行うので、
  影響は IPv4 のインターネットに接続するテスト Pod のみです。
- Dual-stack: `kubernetes` Service は kube-apiserver が作るのと同様に primary
  ファミリの SingleStack です。ノードエージェントは両ファミリの `InternalIP` を
  公開しますが、Pod が受け取るクラスタ DNS（`nameserver`）は primary ファミリの
  ブリッジアドレスだけです（kubelet の `clusterDNS` はリストで、こちらはノードの
  ゲートウェイアドレスをプロファイル順に取る）。
- 共通: API サーバの `kubernetes` Endpoints は同じ uplink アドレスに異なる
  ポートで API サーバごとに 1 アドレスを列挙します（1 ホストに 3 レプリカ）。
  kubeadm は異なるアドレスを列挙します。

## 関連

- [Kubernetes 互換性試験契約](../../spec/verification/kubernetes-compatibility.md)
- [マイルストーン証拠規則](../../spec/delivery/milestones.md)
- [固定したランナー入力](../../third_party/locks/conformance-runners.json)
