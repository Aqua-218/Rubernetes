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
| `cluster.rb up\|start\|down\|delete\|status` | `--root`配下の control 3 ノードと worker 3 ノードを管理する。`exe/rubernetes-*` を使い、PKI、kubeconfig、クラスタ DNS も用意する |
| `netns_env.sh up\|down\|exec` | クラスタごとにネットワーク名前空間を用意する。uplink、NAT、リゾルバが付く |
| `round.sh` | 名前空間の中でHydrophoneのConformanceを1ラウンド実行する。JUnitの合計と失敗したspec名を出力する |
| `run.rb` | K0〜K7の検査を実行し、プロファイルごとの実行マニフェストを書く。`rake m8:lanes`で実行 |
| `build_selection_ledger.rb` | Ginkgoのdry-runからK3の選択台帳を再生成する。`rake m8:selection_ledger`で実行 |
| `resolve_image_digests.rb` | コーパスが使うイメージのタグを、ロック用のダイジェストに解決する |

検査の実装は`k0_input_integrity.rb`、`k5_differential.rb`、`k6_corpus.rb`、`k7_lifecycle.rb`、`lanes.rb`にあります。

K0 は固定版 Kubernetes のクリーンな Git 作業ツリーを使います。固定したランナーイメージと Conformance イメージを確認し、vendor を含む上流 Go ソースからテストイメージを列挙します。クラスタの検査前に、解決したダイジェストを `k0/resolved-images.json` に記録し、`k0/inputs.json` で実行と結び付けます。比較用 kubeconfig が指定されている場合は、クラスタに接続せず、設定されたサーバーと静的な資格情報を比較します。実行後に上流イメージのタグを再確認します。

K6のkubectl検査は、クライアントのバージョンごとに専用のワークロード用namespaceを作成し、検査後に削除します。Podのストリーミング、固定したBusyBoxイメージの取得、`kubectl top`を実行するための`metrics.k8s.io` APIが必要です。
SDKの検査にはGoと固定したclient-goモジュールが必要です。HelmとKustomizeの実行ファイルのパスとチェックサムは`test/compatibility/clients/matrix.yml`にあります。

Cilium の検査は、Rubernetes ワーカーを 1 台動かす専用の QEMU ゲストで行います。
新しいゲストに書き込み可能な CNI ディレクトリと、`/opt/cni/bin` の `loopback` バイナリを用意します。
cgroup v2 と bpffs をマウントし、固定したチャートとイメージの取得先に接続できるようにします。
ゲストのルートには ext4 などの書き込み可能なファイルシステムを使い、
`/srv` にワークロードの overlayfs の書き込み層を置きます。
ゲストの OpenSSL に証明書バンドルの指定が必要な場合は、`SSL_CERT_FILE` にパスを設定します。
ゲスト内で `RUBERNETES_K6_CILIUM_GUEST` にゲストの boot ID を設定し、
`ruby tools/conformance/k6_cilium_guest.rb /path/to/evidence` を実行します。
Cilium が Pod の IP アドレスとデータパスを管理し、Kubernetes Service は Rubernetes の kube-proxy が提供します。
両 Pod の Cilium エンドポイントを確認し、クライアント Pod からサーバーの Pod IP と ClusterIP に HTTP で到達できることを検証します。
オペレーターはホストのヘルスチェックポートを使うため、スケール検査では 1 レプリカを 0 にしてから 1 に戻します。
対象は 1 台のゲスト内の通信です。

## K3 可搬な Linux e2e

1回の実行に含める対象テストは最大32件。通常のテストを全件実行してから、上流の `Serial` ラベルを持つテストを直列に実行する。JUnit の結果は実行ごとに保存する。

K3 は上流プロセスの終了後、書き込みが完了した XML を `junit_*.xml.gz` に圧縮し、元の XML の SHA-256 を記録します。`gzip -dc` で内容を読めます。検証ツールは従来の非圧縮 XML も読み込みます。

各チャンクの完了時にコマンド記録を書き出します。標準出力と標準エラーは、その記録が示す gzip ファイルに保存します。

K3 の HPA リソーステストには、`test/compatibility/clients/matrix.yml` で固定した Helm と kubectl を指定のパスに置き、`cluster.rb up --with-hpa-metrics` で専用クラスタを用意します。K6 コーパスで固定した metrics-server のチャートとイメージを導入し、APIService の準備を待って、全ワーカーの CPU とメモリの実測値を `logs/hpa-node-metrics.json` に記録します。分離ネットワークのワーカーでは kubelet TLS が既定で有効です。ワーカーがネットワークを共有する構成では、起動時に `RUBERNETES_M8_COMPONENT_IDENTITIES=1` を指定します。K6 の metrics-server 検査は、APIService の導入と削除を検証するために別のクラスタで実行します。

選択台帳で対応づけたプロバイダーのストレージテストでは、固定した上流のテストケースを Kubernetes HostPath、NFS、Rook Ceph RBD の CSI ドライバーに対して実行します。ローカルの Linux amd64 ワーカーと上流のチェックアウトが必要です。初回は `skopeo` でダイジェストを固定したドライバーとサイドカーのバイナリを取得します。ワーカーの登録用 Unix ソケットが Linux のパス長制限に収まるよう、クラスタのルートは `/srv` 配下の短いパスにします。Ginkgo と JUnit のレポート、ドライバーのログ、ストレージの削除確認は `csi-replacements/` に保存します。完了したレポートは gzip で可逆圧縮し、実行記録に保存先と圧縮前の SHA-256 を記録します。既存の非圧縮レポートも引き続き検証できます。
HostPath の raw ブロックテストは Linux のループデバイスを使います。ストレステストでは上流指定の 10 Pod をそれぞれ 10 回再起動します。64 GiB の疎なファイルシステム上にブロックボリュームを確保するため、検証ホストで同じ容量を実際に消費せずに実行できます。XFS、ext4、ext3 を指定するテストには、カーネルの対応と各ファイルシステムの `mkfs` が必要です。イメージのスーパーブロックと、カーネルが報告するファイルシステムを記録します。HostPath の拡張テストでは固定した CSI resizer を起動します。NFS の拡張ポリシーテストでは、稼働中の Pod が使う PVC の拡張要求を、StorageClass の設定に従って API が拒否することを確認します。
スナップショットのテストでは、固定した VolumeSnapshot CRD と公式の snapshot-controller、CSI snapshotter を起動します。削除確認には、そのドライバーの VolumeSnapshotContent の残存数も含まれます。
トポロジーのテストには Ready なワーカーが 2 台以上必要です。各ワーカーに公式 CSI ドライバーとノードローカルの provisioner を起動します。同じ要件を宣言する上流ドライバーは、台帳上のテスト ID とソースを維持したまま、同じ公開動作の検証に対応づけます。
共有ファイルシステムのテストには `mount.nfs` を備えた Ready なワーカーが 2 台と、両方から到達できる専用の書き込み可能な NFSv4.1 エクスポートが必要です。接続先を `RUBERNETES_K3_NFS_SERVER` と `RUBERNETES_K3_NFS_SHARE` に指定します。
Azure File の subPath に対応する検証では、同じドライバーで、固定した上流テストのファイル、ディレクトリ、読み取り専用アクセス、マウント解放の動作を確認します。
ワーカー間の RBD テストには、Linux の RBD カーネルドライバーを備えた専用の Rook Ceph 検証クラスタが必要です。`RUBERNETES_K3_RBD_STORAGE_CLASS` に `rook-ceph.rbd.csi.ceph.com` の StorageClass を指定します。Ready な各ワーカーが異なる CSI ノード ID を登録し、個別のマウント名前空間を使います。ファイルシステム、raw ブロック、および両者を組み合わせたボリュームを別ワーカーに付け替え、データを読み戻せることを確認します。テスト後に PV、VolumeAttachment、RBD デバイスが解放されたことを確認します。
復旧テストでは検証環境のノードエージェントを停止して再起動します。Pod の識別子、エージェントの PID、カーネルのマウント、およびデータの読み戻しまたはマウントの解放を記録します。
subPath の削除テストでは、再起動前に CSI のステージングディレクトリを記録し、古い Pod の削除後にステージング領域の一覧が元に戻ったことを確認します。
未使用ボリュームのテストでは、実際に PVC をマウントした Pod を対照にし、PVC の宣言だけを持つ Pod にマウントがないことをカーネルのマウント情報で確認します。

kubelet の認可テストは、Pod からワーカーが公開する IP アドレスの TCP 10250 に直接接続します。ワーカーのエンドポイントには TLS と Webhook 認証・認可を設定します。単一ホストでの実行では `RUBERNETES_M8_COMPONENT_IDENTITIES=1` を指定し、テスト用のネットワーク名前空間内で各ワーカー IP の TCP 10250 を、割り当てられた kubelet のループバックポートに転送できます。

## K4 Node Conformance

固定した Kubernetes v1.36.2 のクリーンなチェックアウトから、upstream のノードテストと Ginkgo をビルドします。

```sh
ruby tools/conformance/build_e2e.rb --node --source-root /path/to/kubernetes-v1.36.2
```

実際の cgroup と network namespace を使う、専用の amd64 Linux テストノードで root として実行します。upstream のシステム検証がノードのファイルシステムを読めるように `/rootfs` に公開します。クラスタには Ready な対象ノードを 1 台置き、API とノードの proxy にアクセスできるテスト用 bearer token を kubeconfig に設定します。

upstream のテストがソケットに直接接続できるよう、エージェントの `device_plugins.directory` を `/var/lib/kubelet/device-plugins` に、`pod_resources.directory` を `/var/lib/kubelet/pod-resources` に設定します。
upstream のランナーは `http://127.0.0.1:10248/healthz` に接続します。構築時に別のポートが割り当てられた場合は `healthz_port: 10248` を設定します。
上流の統計・メトリクスのテストでは `read_only_port: 10255` を設定します。このポートはエージェントの streaming アドレスで診断用の応答を認証なしで提供します。
エージェントを停止・再起動するテストは `sudo systemctl` を直接呼び出します。テスト用エージェントは `kubelet-*` という名前の systemd ユニットで実行します。
ランナーは DNS ドメインと CRI エンドポイントをノードの `/configz` から読み取ります。DNS ドメインが取得できない場合は `cluster.local` を使います。

```sh
ruby tools/conformance/run.rb --lanes K4 --node-conformance-node worker-0 --kubeconfig /path/to/test/kubeconfig
```

upstream の `NodeConformance` のドライランと実行後の Ginkgo レポートを照合し、選択されたテストの未実行、失敗、スキップを記録します。
実行には upstream のノードテストと同じ 24 時間の制限を使います。クラスタの DNS ドメインは対象ノードの `/configz` から読み取り、取得できない場合は `cluster.local` を使います。

検証済みの Ginkgo JSON、出力が完了した JUnit XML、トークンを伏せた実行記録は、元のバイト列を保ったまま `.gz` で保存します。実行結果の各項目には、保存ファイルの `sha256`、展開後の `uncompressed_sha256` と `uncompressed_bytes` が記録されます。圧縮済みファイルは `gzip -dc` で読めます。K4 の読取処理は、過去の非圧縮ファイルにも対応します。不完全なレポートや圧縮後の検証に失敗したレポートは、調査用に元のファイルを保持します。

## K7 ライフサイクル

専用のネットワーク名前空間とcgroupルートを持つ使い捨てクラスタを用意します。
`cluster.rb up --k7-bootstrap`で単一のMemoryStore制御ノードを起動します。K7はこの状態からRaftへ移行し、制御ノードを3台に増やして、各操作の前に書き込んだデータを確認します。
`rake m8:e2e_build`で上流のスモークテスト用バイナリをビルドし、対象クラスタと独立したKubernetes v1.36.2のkubeconfigを`run.rb --lanes K7`に渡します。
K7の実行前に、継続稼働するワークロードのPodがReadyになり、CSIのVolumeAttachmentが`status.attached: true`になるまで待ちます。各操作のあとに、Podのidentityが維持されてReadyに戻ることと、ボリュームがアタッチされたままであることを確認します。

リリースのアップグレードとロールバックには、旧版と1.0.0のデーモンをインストールしたディレクトリを
`RUBERNETES_K7_PREVIOUS_BIN_DIR`と`RUBERNETES_K7_TARGET_BIN_DIR`に指定します。起点のクラスタは`cluster.rb up --k7-bootstrap --bin-dir /path/to/previous/bin`で起動します。

ワーカー再起動を検証するには、ワーカーVMをテストクラスタに参加させ、Node名を`RUBERNETES_K7_REBOOT_NODE`に指定します。
`RUBERNETES_K7_WORKER_REBOOT`にはNode名と現在のカーネル起動IDを受け取り、そのVMをリセットする実行ファイルを指定します。
再起動後は起動IDの変化、Node UIDの維持、Leaseの更新を確認します。

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

K1は`run.rb --lanes K1`で実行し、対象のkubeconfigと固定済みのKubernetesソースを`--source-root`で指定します。ランナーは上流のConformance定義のダイジェストを検証し、元のJUnitとGinkgo JSONをcodenameで照合します。Ginkgo JSONはHydrophoneの出力コンテナから圧縮して`ginkgo-report.json.gz`に保存します。`ginkgo-join.json`には、展開後のJSONのSHA-256と、テスト名・結果・乱数シードの照合結果が入ります。

Hydrophone の標準出力と標準エラーは `hydrophone.stdout.gz` と `hydrophone.stderr.gz` に保存します。失敗時の診断も含め、`gzip -dc` で元のバイト列を読めます。

結果は`junit_01.xml`で確認してください。Hydrophoneは合格したspecについて何も出力しません。ログが止まって見えても、実行は続いています。

修正を確かめるための再実行には`--focus`を使います。`--focus`付きの実行は別の実行として扱われ、全件実行の結果を置き換えません。

上流の Job テストは `/tmp/job-e2e` 配下を hostPath として使います。Rubernetes はマウント境界を越えずに hostPath を検証します。ホストで `/tmp` が独立マウントの場合は、フィクスチャ専用のマウント名前空間でルートファイルシステム上の `/tmp` を使います。

```bash
RUBERNETES_M8_CGROUP_ROOT=/sys/fs/cgroup/conf4 \
  tools/conformance/netns_env.sh exec conf4 -- \
  unshare --mount --propagation private sh -c \
    'umount /tmp && exec ruby tools/conformance/cluster.rb up --profile linux-amd64-ipv4-native --root /srv/rbn-conf4'
```

IPv4プロファイルで外部CNIを検証するには、`cluster.rb up`に`--external-cni-bin-dir /opt/cni/bin`を指定します。プロビジョナは、外部の`bridge`、`host-local`、`loopback`のバージョンとダイジェスト、各ワーカーのCNI設定のダイジェストを記録します。Hydrophoneは通常と同じ条件で実行します。ホストを共有する場合は専用のネットワーク名前空間、cgroupルート、`/run/netns`マウントを用意します。

2026-11-18 UTC の IPv4 native の実行では、v1.36.2 の公式定義に含まれる446件すべてが合格し、スキップ・再試行とも0件でした。スイートのセットアップ・終了処理7件は別に集計します。

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

3 つの native リリースプロファイルでは、ワーカーの隔離が既定です。各ワーカーに専用のネットワーク名前空間、Pod ブリッジ、uplink、kube-proxy を作るので、`hostNetwork` の Pod は別々のワーカーで同じポートを使えます。コントロール側は Pod CIDR を各ワーカーへルーティングし、API サーバは各 Node IP の kubelet に認証付き TLS で接続します。クラスタ内のアドレスはデーモンの HTTP プロキシ除外に追加します。共有ネットワークを使うフィクスチャには `--shared-worker-network` を指定します。外部 CNI と K7 は従来の構成で起動します。`cluster.rb down` は `start` に備えて名前空間を保持します。名前空間も削除する場合は、コントロールの名前空間内で `cluster.rb delete` を使います。

各ワーカーの kubelet は Node IP の 10250 番で認証付き TLS を受け付け、ループバックの 10248 番でヘルスチェックに応答します。kube-proxy は 10256 番で `/healthz` と `/livez` を、ループバックの 10249 番で `/proxyMode` と `/metrics` を提供します。

`cluster.rb up --resolv-conf FILE` を使うと、すべてのワーカーがフィクスチャ専用のリゾルバ設定を使います。クラスタの記録にはファイルのパスと SHA-256 が含まれます。外部 DNS に接続できないフィクスチャでは、外部の検索ドメインを指定しないでください。その名前の解決に失敗すると、クライアントがクラスタ内の名前を試す前に問い合わせを中断することがあります。

```bash
export PATH=/opt/rubies/3.4.11/bin:$PATH            # Gemfileが指定するRuby
export RUBERNETES_M8_CGROUP_ROOT=/sys/fs/cgroup/lanes   # クラスタごとにcgroup rootを1つ
tools/conformance/netns_env.sh up lanes6 --v4 1 --v6 e6   # veth uplink、NAT、resolv.confを用意
tools/conformance/netns_env.sh exec lanes6 -- \
  ruby tools/conformance/cluster.rb up \
  --profile linux-amd64-ipv6-native --root /srv/rbn-lanes
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

専用の`RUBERNETES_M8_CGROUP_ROOT`を持つ新規の隔離Native環境では、`cluster.rb up`に`--retirable-image-cache`を付けられます。K1全件の合格後、検証環境の名前空間で`cluster.rb down --root FIXTURE_ROOT --retire-images-after /path/to/manifest.json`を実行します。K1の記録を検証し、プロセスとワークロードが終了してマウントが解除された後、対象ワーカーのイメージキャッシュを削除して回収バイト数を表示します。通常の`down`はキャッシュを保持するため、失敗時の調査に使えます。

### ホストからクラスタへの接続

ホストからはuplinkのアドレスでクラスタに届きます。URLは`https://10.250.<n>.2:<port>`で、ポートは`cluster.json`に書いてあります。

開発ホストのシェルでは、`http_proxy`がループバック以外のすべての宛先に適用されます。`NO_PROXY=10.250.<n>.2`を設定するか、`curl --noproxy '*'`を使ってください。設定しないと、要求がプロキシに送られて失敗します。

### プロファイルごとの違い

2026-09-27時点でわかっている違いです。

IPv6専用のConformanceプロファイルではNAT64ゲートウェイを使いません。このプロファイルのテストPodからはIPv4の宛先に届きません。イメージはノードエージェントが取得し、ホストのuplinkでは両方のアドレスファミリを使えます。

dual-stackのプロファイルでは、`kubernetes` ServiceはprimaryファミリのSingleStackになります。これはkube-apiserverが作るServiceと同じです。ノードエージェントは両ファミリの`InternalIP`を公開します。一方、Podに渡すクラスタDNSの`nameserver`は、primaryファミリのブリッジアドレスだけです。kubeletの`clusterDNS`は明示したリストですが、Rubernetesはノードのゲートウェイアドレスをプロファイルの順に使います。

すべてのプロファイルに共通の違いもあります。APIサーバの`kubernetes` Endpointsは、同じuplinkアドレスの異なるポートを、APIサーバごとに1件ずつ並べます。1台のホストに3つのレプリカがあるためです。kubeadmで作ったクラスタでは、異なるアドレスが並びます。

## 関連

- [Kubernetes互換性の試験契約](../../spec/verification/kubernetes-compatibility.md)
- [マイルストーンの証拠の規則](../../spec/delivery/milestones.md)
- [固定したランナーの入力](../../third_party/locks/conformance-runners.json)
