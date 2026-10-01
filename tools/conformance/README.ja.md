# Conformance ツール境界

[English](README.md) | 日本語

固定した upstream 入力の検証、リリース構成クラスタの起動、固定した
Hydrophone / Sonobuoy バイナリと upstream `e2e.test` の実行、JUnit/Ginkgo 出力の
正規化、upstream e2e 一覧の分類、M8 証拠マニフェストの出力を行う Ruby
コマンド群です。

ツールは upstream の実行ファイルを指揮してよいが、そのソース、focus、skip
式、結果を改変してはならない。失敗または不完全な upstream 実行は失敗のまま
とする。

| コマンド | 役割 |
|---|---|
| `lock.rb` | `third_party/locks/` の読み取り専用ビュー（Kubernetes コミット、Conformance イメージのダイジェスト、ランナー成果物） |
| `install_tools.rb`（`rake m8:tools`） | Hydrophone と Sonobuoy を `build/conformance/bin` に導入。各アーカイブをロックと照合 |
| `build_e2e.rb`（`rake m8:e2e_build`） | 固定したチェックアウトから upstream `e2e.test` をビルド |
| `cluster.rb up\|down\|status` | 本物の `exe/rubernetes-*` プロセスによる control 3 + worker 3 クラスタを、PKI・kubeconfig・クラスタ DNS 込みで `--root` 配下に起動／停止 |
| `netns_env.sh up\|down\|exec` | クラスタインスタンスごとに uplink・NAT・リゾルバ付きのネットワーク名前空間を用意 |
| `round.sh` | 名前空間内で Hydrophone の Conformance を 1 ラウンド実行し、JUnit の合計と失敗 spec 名を出力 |
| `run.rb`（`rake m8:lanes`） | プロファイルごとの実行マニフェストを書く公式 K1〜K7 レーンランナー |
| `k0_input_integrity.rb`、`k5_differential.rb`、`k6_corpus.rb`、`k7_lifecycle.rb`、`lanes.rb` | レーンの実装 |
| `build_selection_ledger.rb`（`rake m8:selection_ledger`） | Ginkgo の dry-run から K3 選択台帳を再生成 |
| `resolve_image_digests.rb` | プロジェクトコーパスのイメージタグをロック用のダイジェストに解決 |

## 日常のループ

```bash
export PATH=/opt/rubies/3.4.11/bin:$PATH
rake m8:tools                                               # hydrophone + sonobuoy、1 回だけ
tools/conformance/netns_env.sh up conf4 --v4 3 --v6 e7      # クラスタインスタンスごとに名前空間 1 つ
RUBERNETES_M8_CGROUP_ROOT=/sys/fs/cgroup/conf4 \
  tools/conformance/netns_env.sh exec conf4 -- \
  ruby tools/conformance/cluster.rb up --profile linux-amd64-ipv4-native --root /srv/rbn-conf4
setsid nohup tools/conformance/round.sh conf4 /srv/rbn-conf4/linux-amd64-ipv4-native \
  /srv/rbn-conf4/rounds/01 --parallel 4 > /srv/rbn-conf4/rounds/01.out 2>&1 &
```

`--parallel 4` のフルラウンドは 1 ホストで約 40 分です。結果は `junit_01.xml` を
読んでください。Hydrophone のログでは合格は何も出力しないので、静かなログは
停止ではありません。修正の再実行は `--focus` で行います（別の実行 identity で
あり、フルラウンドの結果を置き換えることはありません）。このツリーでの直近の
IPv4 フルラウンドは 459/459 合格（2026-09-30）。

## IPv6 と dual-stack プロファイルの起動

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
