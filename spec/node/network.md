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

<a id="sec-5-9-7"></a>
## 5.9.7 DNS

- cluster domainの既定値は`cluster.local`とする。positive TTLとnegative TTLの既定値は、どちらも5秒とする。
- Service、EndpointSlice、Podをwatchする。`<svc>.<ns>.svc.<domain>`に対してA、AAAA、SRV、PTRを返す。
- headless Serviceでは、readyなendpointのPod IPを返す。`publishNotReadyAddresses`が指定されていれば、readyでないendpointも返す。
- ExternalNameにはCNAMEを返す。Podのhostnameとsubdomain、StatefulSetの安定した名前は、Kubernetesの規則で生成する。
- `dnsPolicy`、`dnsConfig`、`hostNetwork`に応じたnameserver、search、optionを、`/etc/resolv.conf`にatomicに書き出す。
- クラスタ外への問い合わせは、設定済みのupstreamに転送する。転送するときはtransaction IDを生成し直す。ループ、応答の偽装、大きすぎるパケットは拒否する。

## 関連

- [service proxy](service-proxy.md)
- [runtime](runtime.md)
- [06 network](../diagrams/06-network.md)
