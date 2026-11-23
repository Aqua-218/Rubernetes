[仕様書の目次](../README.md) / [ノード](README.md)

<a id="sec-5-9"></a>
# 5.9 ネットワーク

> 対象読者: ネットワークの実装者、セキュリティの検証者
>
> 状態: 規範、版0.2

Rubyによるnetlinkの実装、IPAM、オーバーレイ、NetworkPolicy、DNSを定義する。ネットワークは自作する。

図は[図06 ネットワーク](../diagrams/06-network.md)にある。

<a id="sec-5-9-1"></a>
## 5.9.1 インターフェース

```text
add(sandbox, config)   → ip, routes
delete(sandbox)
check(sandbox)         → bool
recover                → recovery_report
```

各操作は、サンドボックスIDとネットワーク操作IDで冪等にする。

リンク、アドレス、経路、FDB、BPFマップ、IPのリースは、owned resourceとして扱う。[5.8.4](runtime.md#sec-5-8-4)の台帳に記録する。

プロセスまたはVMの停止を確認するまで、IPとインターフェースのidentityを再利用してはならない。

<a id="sec-5-9-2"></a>
## 5.9.2 netlink

- `AF_NETLINK`ソケットを直接開く。
- メッセージヘッダと属性（TLV）を自前で組み立てる。
- 応答の`NLMSG_ERROR`を必ず検査する。

使うメッセージ種別は、`RTM_NEWLINK`、`RTM_DELLINK`、`RTM_NEWADDR`、`RTM_NEWROUTE`、`RTM_SETLINK`である。

<a id="sec-5-9-3"></a>
## 5.9.3 Podネットワークの構築

1. vethのペアを作る。
2. 片方をPodのnetwork namespaceに移す。
3. Pod側にIPを割り当て、リンクをupにする。
4. ホスト側をブリッジに接続する。
5. デフォルトルートを設定する。

<a id="sec-5-9-4"></a>
## 5.9.4 IPAM

- cluster CIDRのIPv4とIPv6のサブネットを、ノードごとに重複なく割り当てる。
- ノードの中では、PodのサンドボックスIDに対してIPを予約する。ネットワークに接続したあとで確定し、停止を確認したあとで解放する。
- リースは`{family,ip,pod_uid,sandbox_id,operation_id,state}`の形でfsyncする。再起動時には、kernelのリンクと経路に照合する。
- dual-stackのPodでは、両ファミリの取得を1つのトランザクションにする。片方が失敗したら両方を取り消す。
- 同時に確定しているIPは重複しない。解放する前や、古いサンドボックスが生きている間は、IPを再利用しない。この性質はLeanで証明する。[7.3](../verification/formal-methods.md#sec-7-3)を参照。

<a id="sec-5-9-5"></a>
## 5.9.5 オーバーレイ

`vxlan`と`host-gw`の2つのbackendを、Rubyのnetlink実装で提供する。

`Auto`を指定した場合は、次のように選ぶ。すべてのノードが同じL2にあり、next-hopで到達できるなら`host-gw`を使う。そうでなければVXLANを使う。

VXLANの既定値は次のとおりである。

| 項目 | 既定値 |
|---|---|
| VNI | 4096 |
| UDPポート | 4789 |
| MTU | underlayのMTUから、IPv4では50 byte、IPv6では70 byteを引いた値 |

各ノードのVTEP、対向のサブネット、FDB、経路は、NodeとLeaseのwatchのリビジョンに対応付けて、差分だけを更新する。

ノードを削除するときは、経路とFDBを消す前に、そのノードのPod IPをEndpointSliceとconntrackから取り除く。

<a id="sec-5-9-6"></a>
## 5.9.6 NetworkPolicy

- `podSelector`、`namespaceSelector`、両者の組み合わせ、`ipBlock`と`except`を実装する。
- ingressとegress、TCP・UDP・SCTP、名前付きポート、`endPort`、IPv4とIPv6を扱う。
- ポリシーの対象になっていない方向の通信は許可する。1つ以上のポリシーが選択した方向では、ルールの和集合に含まれる通信だけを許可する。
- selectorから得たidentityの集合を、eBPFマップまたはnftablesのsetに反映する。反映はリビジョン単位で、atomicに入れ替える。
- default-denyを更新するときに、一時的にすべての通信を許可する時間を作ってはならない。

内蔵ネットワークは、起動時にPod、Namespace、NetworkPolicyを取得し、以降は各リソースの `resourceVersion` から変更を監視する。異なるノードのPodは通信相手の選択に使い、各ワーカーは自身が管理するPodへルールを適用する。

`rubectl cluster` はコンポーネント認証を使うクラスタに専用の読み取り資格情報を設定する。ノードを個別に構成する場合は、`network.policy_kubeconfig` に読み取り用kubeconfigの絶対パスを指定する。認証主体には [NetworkPolicy用のClusterRole](../../config/addons/network-policy-rbac.yml) と同じ `list`、`watch` の権限が必要になる。省略した場合はノードエージェントのAPIクライアントを使用する。

<a id="sec-5-9-7"></a>
## 5.9.7 DNS

- cluster domainの既定値は`cluster.local`とする。positive TTLとnegative TTLの既定値は、どちらも5秒とする。
- Service、EndpointSlice、Podをwatchする。`<svc>.<ns>.svc.<domain>`に対してA、AAAA、SRV、PTRを返す。
- headless Serviceでは、readyなendpointのPod IPを返す。`publishNotReadyAddresses`が指定されていれば、readyでないendpointも返す。
- ExternalNameにはCNAMEを返す。Podのhostnameとsubdomain、StatefulSetの安定した名前は、Kubernetesの規則で生成する。
- `dnsPolicy`、`dnsConfig`、`hostNetwork`に応じたnameserver、search、optionを、`/etc/resolv.conf`にatomicに書き出す。
- クラスタ外への問い合わせは、設定済みのupstreamに転送する。転送するときはtransaction IDを生成し直す。ループ、応答の偽装、大きすぎるパケットは拒否する。

<a id="sec-5-9-8"></a>
## 5.9.8 CNIプラグイン

ノードエージェントは、設定で`network.plugin: cni`を指定した場合、内蔵のbridgeの代わりにCNIプラグインを実行する。既定は内蔵のbridgeである。

```yaml
network:
  plugin: cni
  state_path: /var/lib/rubernetes/network/state.json
  cni:
    conf_dir: /etc/cni/net.d
    bin_dirs: [/opt/cni/bin]
```

エージェントはCNI仕様1.0のランタイムとして振る舞う。

- ネットワークは、`conf_dir`にある設定ファイルのうち、名前順で最初のものとする。対象は`.conflist`、`.conf`、`.json`である。プラグイン1つだけの設定は、要素が1つのリストとして扱う。
- ADDでは、最初に`loopback`を実行し、続けて設定のプラグインを順に実行する。各プラグインには、直前のプラグインの結果を`prevResult`として渡す。
- DELでは、プラグインを逆順に実行する。渡すのは、ADDのときの設定と、ADDの最後の結果である。この2つはsandboxごとにディスクに保存する。エージェントが再起動していても、設定ファイルが書き換わっていても、DELはADDと同じネットワークに対して行う。
- ADDが途中で失敗した場合は、そこまでのプラグインにDELを実行し、ADDの失敗を報告する。
- 設定にあるプラグインの実行ファイルが`bin_dirs`にない場合は、どのプラグインも実行せずに失敗させる。
- CHECKは、`cniVersion`が0.4.0以上のネットワークに対して実行する。
- `CNI_ARGS`には、`K8S_POD_NAMESPACE`、`K8S_POD_NAME`、`K8S_POD_INFRA_CONTAINER_ID`、`K8S_POD_UID`を渡す。
- `portMappings`のcapabilityを宣言したプラグインには、PodのhostPortを`runtimeConfig`で渡す。
- `hostNetwork`のPodには、プラグインを実行しない。

CNIを使う場合、Podのアドレス、経路、ノードのbridge、NetworkPolicyは、プラグインが受け持つ。[5.9.3](network.md#sec-5-9-3)から[5.9.6](network.md#sec-5-9-6)の内蔵の実装は動かない。Podが問い合わせるクラスタDNSのアドレスは`dns.cluster_dns`に指定する。内蔵のDNSサーバーを起動する場合は、`dns.bind_addresses`にノード側の待ち受けアドレスを指定する。既存のクラスタDNSを使う場合は、`dns.enabled: false`で内蔵のDNSサーバーを無効にできる。

この構成は、既存の環境へ組み込むための接続口である。互換性を検証する構成には含めない。

<a id="sec-5-9-9"></a>
## 5.9.9 IPv6専用Podからの送信

IPv6専用Podから名前でIPv4の宛先に接続する場合は、既存のNAT64ゲートウェイとノードのDNS64を組み合わせる。クラスタを作成するときは、ゲートウェイの変換プレフィックスを指定する。

```sh
rubectl cluster up --ip-family ipv6 --nat64-prefix 64:ff9b:1::/96
```

個別のノードを構成する場合は、エージェントの設定に同じ値を指定する。

```yaml
dns:
  nat64_prefix: 64:ff9b:1::/96
```

各ノードのIPv6経路で、そのプレフィックスをNAT64ゲートウェイへ向ける。ゲートウェイにはIPv4宛先への到達性と、送信元IPv6アドレスへの戻り経路が必要である。内蔵bridgeのPodは既存のIPv6デフォルト経路を使う。プレフィックスにはPodやServiceのCIDRと重複しないものを選ぶ。RFC 6052の`64:ff9b::/96`はグローバルなIPv4宛先専用である。プライベートなIPv4宛先へ接続するには、ゲートウェイでサイト専用プレフィックスを設定する。

外部名へのAAAA問い合わせが`NOERROR`で、応答にAAAAがなければ、クラスタDNSはAを問い合わせ、ゲートウェイのプレフィックスでAAAAを合成する。既存のAAAAやクラスタ内のアドレスはそのまま返す。DNSSECフラグ付きの問い合わせは通常どおり転送する。IPv4リテラルへの接続に必要なCLATは別途構成する。

## 関連

- [サービスプロキシ](service-proxy.md)
- [ランタイム](runtime.md)
- [06 ネットワーク](../diagrams/06-network.md)
