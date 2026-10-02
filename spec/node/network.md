[仕様書の目次](../README.md) / [ノード](README.md)

<a id="sec-5-9"></a>
# 5.9 ネットワーク

> 対象読者: ネットワークの実装者、セキュリティの検証者
>
> **Status:** Normative — version 0.2

Ruby netlink、IPAM、overlay、NetworkPolicy、DNSを定義する。


> **Diagram:** [図 06 — Network](../diagrams/06-network.md)

<a id="sec-5-9-1"></a>
## 5.9.1 インターフェース

```text
add(sandbox, config)   → ip, routes
delete(sandbox)
check(sandbox)         → bool
recover                → recovery_report
```

各操作は sandbox ID と network operation ID で冪等化する。link、address、route、FDB、BPF map、
IP lease を owned resource として [§5.8.4](runtime.md#sec-5-8-4) の ledger に参加させ、process/VM の停止確認前に
IP と interface identity を再利用してはならない。

<a id="sec-5-9-2"></a>
## 5.9.2 netlink

- `AF_NETLINK` ソケットを直接開く
- メッセージヘッダと属性（TLV）を自前で組み立てる
- 応答の `NLMSG_ERROR` を必ず検査する
- 使用するメッセージ種別: `RTM_NEWLINK`、`RTM_DELLINK`、`RTM_NEWADDR`、`RTM_NEWROUTE`、`RTM_SETLINK`

<a id="sec-5-9-3"></a>
## 5.9.3 Pod ネットワーク構築

1. veth pair を作成する
2. 一方を Pod の network namespace へ移動する
3. Pod 側に IP を割り当て、up にする
4. ホスト側をブリッジに接続する
5. デフォルトルートを設定する

<a id="sec-5-9-4"></a>
## 5.9.4 IPAM

- cluster CIDR の IPv4/IPv6 subnet を node ごとに重複なく割り当てる
- node 内で Pod sandbox ID に対して IP を reserve、network 接続後に commit、停止確認後に release する
- lease は `{family,ip,pod_uid,sandbox_id,operation_id,state}` として fsync し、再起動時に kernel link/route と照合する
- dual-stack Pod では両 family の取得を 1 transaction とし、片方の失敗時に両方を rollback する
- 同時に commit 済みの IP は重複しない。release 前または旧 sandbox の生存中に再利用しない（Lean、[§7.3](../verification/formal-methods.md#sec-7-3)）

<a id="sec-5-9-5"></a>
## 5.9.5 オーバーレイ

- `vxlan` と `host-gw` の両 backend を Ruby netlink 実装で提供する
- `Auto` は全 node が同一 L2 で next-hop 到達可能なら `host-gw`、それ以外は VXLAN を選ぶ
- VXLAN は VNI 4096、UDP port 4789 を既定とし、underlay MTU から IPv4 は 50 byte、IPv6 は 70 byte を差し引く
- 各 node の VTEP、対向 subnet、FDB、route を Node/Lease watch の revision と対応付けて差分更新する
- node 削除時は route/FDB を削除する前に、その node の Pod IP を EndpointSlice と conntrack から除外する

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
