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

## NodePortの割り当て

NodePortの既定の範囲は30000〜32767とする。割り当ては1つのストアトランザクションで確定する。dual-writeは行わない。

## ルールの適用

ルールは差分だけを適用する。すべて消して書き直すことはしない。

## backend

- eBPF backendでは、RubyでeBPFの命令列とマップのレイアウトを生成する。`bpf(2)`でTCとcgroupのフックにattachする。
- eBPFを使えないノードでは、nftables backendを使う。nftablesのメッセージは、Rubyのnetlinkエンコーダで組み立てる。
- `Auto`を指定した場合は、eBPF verifierのプローブが成功すればeBPFを選ぶ。失敗すればnftablesを選ぶ。選んだ結果はノードのstatusに記録する。
- eBPFとnftablesは、Serviceの意味論を確かめる同じテストコーパスを通過しなければならない。

## 関連

- [ネットワーク](network.md)
- [Kubernetes API](../api/kubernetes-api.md)
- [06 ネットワーク](../diagrams/06-network.md)
