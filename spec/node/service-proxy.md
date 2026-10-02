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

- [network](network.md)
- [kubernetes api](../api/kubernetes-api.md)
- [06 network](../diagrams/06-network.md)
