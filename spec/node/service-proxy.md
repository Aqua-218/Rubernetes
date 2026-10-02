[仕様書の目次](../README.md) / [ノード](README.md)

<a id="sec-5-10"></a>
# 5.10 サービスプロキシ

> 対象読者: Serviceのデータパスの実装者
>
> 状態: 規範、版0.2

Service/EndpointSlice、conntrack、eBPF/nftables backendの互換動作を定義する。


- Service と EndpointSlice を watch する
- ClusterIP、headless、NodePort、LoadBalancer、ExternalIP、ExternalName と IPv4/IPv6 dual-stack を処理する
- TCP、UDP、SCTP の ClusterIP/NodePort 宛 packet を healthy endpoint へ変換する
- 接続追跡を自前で保持し、同一接続を同一 Pod へ送る
- 分散方式は backend 集合上の決定的 hash とし、`sessionAffinity: ClientIP` は timeoutSeconds と送信元 IP で固定する
- `internalTrafficPolicy`、`externalTrafficPolicy`、topology aware hint、terminating endpoint、healthCheckNodePort を反映する
- NodePort の既定範囲は 30000〜32767 とし、allocation は dual-write を行わず 1 Store transaction で確定する
- ルールは差分適用する。全消し全書きをしない
- Ruby で eBPF instruction と map layout を生成し、`bpf(2)` で TC/cgroup hook へ attach する
- eBPF を利用できない node では Ruby netlink encoder による nftables backend を用いる
- `Auto` の backend 選択は eBPF verifier probe 成功時に eBPF、失敗時に nftables とし、node status に記録する
- eBPF と nftables は同一の Service semantics test corpus を通過しなければならない

## Related

- [network](network.md)
- [kubernetes api](../api/kubernetes-api.md)
- [06 network](../diagrams/06-network.md)
