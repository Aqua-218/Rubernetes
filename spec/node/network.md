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

- `podSelector`、`namespaceSelector`、両者の conjunction、`ipBlock` と `except` を実装する
- ingress/egress、TCP/UDP/SCTP、named port、`endPort`、IPv4/IPv6 を扱う
- policy 対象でない方向は allow、1 個以上の policy が選択した方向は rule の和集合だけを allow する
- selector から得た identity set を eBPF map または nftables set へ revision 単位で atomic swap する
- default-deny 更新時に一時的な allow-all window を作ってはならない

<a id="sec-5-9-7"></a>
## 5.9.7 DNS

- cluster domain の既定を `cluster.local`、positive/negative TTL の既定を各 5 秒とする
- Service/EndpointSlice/Pod を watch し、`<svc>.<ns>.svc.<domain>` の A、AAAA、SRV、PTR を返す
- headless Service は ready endpoint の Pod IP、publishNotReadyAddresses 指定時は not-ready も返す
- ExternalName は CNAME、Pod hostname/subdomain と StatefulSet の stable name を Kubernetes 規則で生成する
- `dnsPolicy`、`dnsConfig`、`hostNetwork` に応じた nameserver、search、option を `/etc/resolv.conf` へ atomic 投影する
- cluster 外 query は設定済み upstream へ transaction ID を再生成して転送し、loop、response spoof、過大 packet を拒否する

## Related

- [service proxy](service-proxy.md)
- [runtime](runtime.md)
- [06 network](../diagrams/06-network.md)
