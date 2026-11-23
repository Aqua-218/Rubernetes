[仕様書の目次](../README.md) / [ノード](README.md)

<a id="sec-5-10"></a>
# 5.10 サービスプロキシ

> 対象読者: Serviceのデータパスの実装者
>
> 状態: 規範、版0.2

ServiceとEndpointSlice、conntrack、eBPFとnftablesの各backendについて、互換な動作を定義する。

## 対象

ServiceとEndpointSliceをwatchする。次の種類のServiceを処理する。

- ClusterIP
- headless
- NodePort
- LoadBalancer
- ExternalIP
- ExternalName

IPv4とIPv6のdual-stackにも対応する。

## パケットの転送

- ClusterIPまたはNodePort宛のTCP、UDP、SCTPのパケットを、正常なendpoint宛に変換する。
- 接続の追跡を自前で保持する。同じ接続のパケットは同じPodに送る。
- 分散先は、backendの集合に対する決定的なハッシュで選ぶ。
- `sessionAffinity: ClientIP`の場合は、送信元IPごとに分散先を固定する。固定する時間は`timeoutSeconds`に従う。
- `internalTrafficPolicy`、`externalTrafficPolicy`、topology aware hint、terminating endpoint、`healthCheckNodePort`を反映する。
- LoadBalancerのVIPは`status.loadBalancer.ingress`の`ip`で決まる。`ipMode: Proxy`のIPへの転送はクラウドプロバイダが担う。
- Pod が Service 経由で自分自身に到達する場合、選ばれた endpoint に対して送信元 NAT を適用する。内蔵ブリッジは Pod の veth で hairpin を有効にする。

## NodePortの割り当て

NodePortの既定の範囲は30000〜32767とする。割り当ては1つのストアトランザクションで確定する。dual-writeは行わない。

## ルールの適用

ルールは差分だけを適用する。すべて消して書き直すことはしない。

## backend

- eBPF backendでは、RubyでeBPFの命令列とマップのレイアウトを生成する。`bpf(2)`でTCとcgroupのフックにattachする。
- eBPFを使えないノードでは、nftables backendを使う。nftablesのメッセージは、Rubyのnetlinkエンコーダで組み立てる。
- `Auto`を指定した場合は、eBPF verifierのプローブが成功すればeBPFを選ぶ。失敗すればnftablesを選ぶ。選んだ結果はノードのstatusに記録する。
- eBPFとnftablesは、Serviceの意味論を確かめる同じテストコーパスを通過しなければならない。
- 既定の nftables backend は、Service NAT の前に Linux が IP 断片を再構成する。Linux の eBPF アダプターも断片をカーネルに渡し、UDP は未分割のデータグラムも同じ conntrack で追跡する。
- M4 の断片拒否試験は、両 backend の明示的な `reject` ポリシーを使い、再構成前に断片を破棄する動作を確認する。

## 関連

- [ネットワーク](network.md)
- [Kubernetes API](../api/kubernetes-api.md)
- [06 ネットワーク](../diagrams/06-network.md)
