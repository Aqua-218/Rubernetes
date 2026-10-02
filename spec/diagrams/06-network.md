[仕様書の目次](../README.md) / [構成図](README.md)

<a id="sec-a-6"></a>
# A.6 図06 ネットワーク

> 対象読者: ネットワークとServiceの実装者
>
> 状態: 規範、版0.2

netlink、IPAM、Podネットワーク、オーバーレイ、NetworkPolicy、DNS、サービスプロキシを示す。

```mermaid
graph TB

IF["Network Interface ◇自作 backend<br/>ADD · DEL · CHECK · RECOVER"]
IF --> IPAM1

subgraph NL["◤ netlink ◆自作 ◢"]
    L1["<b>ソケット</b><br/>AF_NETLINK / NETLINK_ROUTE<br/>bind · sequence 管理"]
    L2["<b>メッセージ組立</b><br/>nlmsghdr 手組み<br/>flags: REQUEST/ACK/CREATE/EXCL"]
    L3["<b>属性 TLV</b><br/>rtattr の入れ子<br/>アラインメント計算<br/>型付きエンコード / デコード"]
    L4["<b>RTM_*LINK</b><br/>デバイス作成 · 削除<br/>up/down · MTU · ns 移動"]
    L5["<b>RTM_*ADDR</b><br/>IP 付与 · 削除"]
    L6["<b>RTM_*ROUTE</b><br/>経路追加 · 削除<br/>テーブル · メトリック"]
    L7["<b>RTM_*NEIGH</b><br/>ARP / FDB エントリ"]
    L8["<b>応答処理</b><br/>multipart 受信<br/>NLMSG_ERROR 判定"]
end

subgraph IPAMG["◤ IPAM ◢"]
    IPAM1["<b>クラスタ CIDR 分割</b><br/>ノード毎サブネット割当"]
    IPAM2["<b>Pod IP 払出</b><br/>ビットマップ管理<br/>予約 · 確定 · 解放"]
    IPAM3["<b>永続化</b><br/>再起動後の再構成<br/>リーク検出 · GC"]
end

subgraph POD["◤ Pod ネットワーク構築 ◢"]
    V1["<b>veth pair 生成</b><br/>片側をコンテナ netns へ移動"]
    V2["<b>netns 内設定</b><br/>IP 付与 · lo up<br/>デフォルト経路"]
    V3["<b>ホスト側</b><br/>bridge へ接続 · up<br/>MAC 設定"]
    V4["<b>bridge</b><br/>作成 · IP 付与<br/>MAC 学習 · STP 無効"]
    V5["<b>sysctl</b><br/>ip_forward · rp_filter<br/>bridge-nf 設定"]
    V6["<b>hostNetwork の場合</b><br/>ns 分離を省略"]
end

subgraph OVER["◤ オーバーレイ ◢"]
    O1["<b>VXLAN デバイス</b><br/>VNI · dstport · learning off"]
    O2["<b>FDB 管理</b><br/>ノード MAC → リモート IP<br/>ノード追加時に更新"]
    O3["<b>経路配布</b><br/>ノードのサブネットを watch<br/>各ノードに経路追加"]
    O4["<b>MTU 調整</b><br/>カプセル化分の減算<br/>PMTU 対応"]
    O5["<b>代替: host-gw</b><br/>同一 L2 なら直接経路"]
end

subgraph POL["◤ NetworkPolicy ◢"]
    Y1["<b>ポリシー評価</b><br/>podSelector · namespaceSelector<br/>ingress / egress ルール"]
    Y2["<b>ルール展開</b><br/>Pod IP 集合へ解決<br/>差分更新"]
    Y3["<b>既定拒否</b><br/>ポリシー対象 Pod の扱い"]
end

subgraph DNSG["◤ DNS ◢"]
    D1["<b>権威応答</b><br/>svc.ns.svc.cluster.local<br/>A · AAAA · SRV · PTR"]
    D2["<b>headless Service</b><br/>Pod IP 群を直接返す"]
    D3["<b>Service / Endpoint を watch</b><br/>ゾーンの動的更新"]
    D4["<b>上流フォワード</b><br/>クラスタ外名の委譲<br/>キャッシュ · TTL"]
    D5["<b>resolv.conf 注入</b><br/>ndots · search ドメイン"]
end

subgraph PROXY["◤ Service Proxy ◢"]
    R1["<b>Service / EndpointSlice watch</b><br/>差分の算出"]

    subgraph MODE1["実装 A: netfilter 相当"]
        R2["<b>DNAT テーブル自前管理</b><br/>ClusterIP → Pod IP<br/>ルールの差分適用"]
        R3["<b>conntrack</b><br/>接続追跡テーブル保持<br/>タイムアウト · 期限切れ回収<br/>Endpoint 削除時の破棄"]
        R4["<b>SNAT / masquerade</b><br/>ノード外への出口"]
        R5["<b>NodePort · ExternalIP</b>"]
    end

    subgraph MODE2["実装 B: eBPF ◆"]
        B1["<b>BPF 命令列を自前生成</b><br/>命令エンコーダ<br/>レジスタ割付 · 分岐解決"]
        B2["<b>bpf(2) syscall</b><br/>BPF_PROG_LOAD<br/>BPF_MAP_CREATE / UPDATE<br/>verifier ログ回収"]
        B3["<b>MAP 設計</b><br/>service → backend 配列<br/>conntrack ハッシュ<br/>per-cpu 統計"]
        B4["<b>アタッチ</b><br/>TC ingress/egress<br/>cgroup connect hook"]
        B5["<b>負荷分散ロジック</b><br/>ハッシュ選択 · セッション固定<br/>健全 backend のみ"]
        B6["<b>観測</b><br/>perf ring buffer<br/>ドロップ理由の可視化"]
    end

    R6["<b>負荷分散</b><br/>round-robin · random<br/>topology aware"]
    R7["<b>健全性反映</b><br/>readiness で backend 出し入れ<br/>terminating の graceful 除外"]
end

L1 --> L2 --> L3
L3 --> L4
L3 --> L5
L3 --> L6
L3 --> L7
L8 -.-> L1

IPAM1 --> IPAM2 --> IPAM3
IPAM2 --> V1
V1 --> V2
V1 --> V3 --> V4
V5 -.-> V4
V6 -.-> V1
V1 -.-> L4
V2 -.-> L5
V3 -.-> L4
V4 -.-> L4

V4 --> O1 --> O2 --> O3
O4 -.-> O1
O5 -.-> O3
O1 -.-> L4
O2 -.-> L7
O3 -.-> L6

Y1 --> Y2 --> Y3
Y2 -.-> R2
Y2 -.-> B3

D3 --> D1 --> D2
D4 -.-> D1
D5 -.-> D1
D1 -.-> IF

R1 --> R2 --> R3
R2 --> R4
R5 -.-> R2
R1 --> B1 --> B2 --> B3 --> B4
B5 -.-> B3
B6 -.-> B4
R6 -.-> R2
R6 -.-> B5
R7 -.-> R6
R2 -.-> L6

classDef nl fill:#1b1630,stroke:#8b6ef0,color:#e6ecf5
classDef ip fill:#1d2431,stroke:#7f8da5,color:#e6ecf5
classDef pd fill:#12202e,stroke:#4b9fd6,color:#e6ecf5
classDef ov fill:#16202a,stroke:#4b9fd6,color:#e6ecf5
classDef po fill:#22200f,stroke:#c9b02a,color:#e6ecf5
classDef dn fill:#101c1a,stroke:#3fae8f,color:#e6ecf5
classDef px fill:#241320,stroke:#e0294b,color:#e6ecf5
classDef bp fill:#2a1a24,stroke:#ff5c78,color:#e6ecf5

class IF ip
class L1,L2,L3,L4,L5,L6,L7,L8 nl
class IPAM1,IPAM2,IPAM3 ip
class V1,V2,V3,V4,V5,V6 pd
class O1,O2,O3,O4,O5 ov
class Y1,Y2,Y3 po
class D1,D2,D3,D4,D5 dn
class R1,R2,R3,R4,R5,R6,R7 px
class B1,B2,B3,B4,B5,B6 bp
```

## Related

- [network](../node/network.md)
- [service proxy](../node/service-proxy.md)
- [構成図インデックス](README.md)
