[仕様書の目次](README.md)

<a id="sec-12"></a>
# 12. 規範参照と設計の由来

> 対象読者: すべての実装者、検証者、仕様編集者
>
> 状態: 規範、版0.2

固定する外部仕様、比較対象、設計の由来、参照の優先順位を定義する。

## 固定する外部仕様

| 参照 | 固定する対象 | 本書での役割 |
|---|---|---|
| [Ruby 3.4.11](https://www.ruby-lang.org/en/news/2026/09/23/ruby-3-4-11-released/) | ソースのSHA-256 `5c22be44524312b3d433d68739bcc530633b1da5ef8ba0afa0a37680da17d3de` | 開発とCIで使うランタイム。RubyのAPIとABIの基準 |
| [Kubernetes](https://github.com/kubernetes/kubernetes/tree/v1.36.2) | タグ`v1.36.2` | API、コントローラ、スケジューラ、ノードの互換性の比較対象 |
| [Kubernetes Conformance](https://github.com/kubernetes/kubernetes/blob/v1.36.2/test/conformance/testdata/conformance.yaml) | 446件、SHA-256 `cdbad746df8e8f5f7e63ef147b579e921c1ad70a68d826f2b9c5af27dbbf7641` | リリースの適合試験 |
| [CNCFのConformanceの手順](https://github.com/cncf/k8s-conformance/blob/691d9b951a75accf18dfc29b811a3947db874081/instructions.md) | コミット`691d9b951a75accf18dfc29b811a3947db874081`、ファイルのSHA-256 `77c5bc20e5702497ee82db64a6c9115862709974921ffea8d46230e92462c18e` | スキップなしの提出形式と、必要な証拠 |
| [Hydrophone](https://github.com/kubernetes-sigs/hydrophone/tree/v0.7.0) | タグ`v0.7.0`、コミット`3de3e886a2f6f09635d8b981c195490af1584d97` | Conformanceを直接実行するランナー |
| [Sonobuoy](https://github.com/vmware-tanzu/sonobuoy/tree/v0.57.5) | タグ`v0.57.5`、コミット`310c51d9874a4d10d021ec8a19f8b42292ec0bfc` | CNCF形式のConformanceの証拠 |
| [Kubernetesのversion-skew policy](https://kubernetes.io/releases/version-skew-policy/) | 2026-08-22に取得 | kubectlとクライアントコンポーネントのテストの組み合わせ |
| [Kubernetesの大規模クラスタの上限](https://kubernetes.io/docs/setup/best-practices/cluster-large/) | v1.36のドキュメント | [1.5](foundation/goals-and-compatibility.md#sec-1-5)の規模の上限 |
| [OCI Image Spec](https://github.com/opencontainers/image-spec/tree/v1.1.1) | タグ`v1.1.1` | イメージのマニフェスト、config、レイヤ |
| [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec/tree/v1.1.1) | タグ`v1.1.1` | レジストリのプロトコル |
| [Linux UAPI](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/?h=v6.12) | タグ`v6.12` | システムコール番号、フラグ、構造体のレイアウト |
| [Firecracker](https://github.com/firecracker-microvm/firecracker/tree/v1.16.1) | タグ`v1.16.1`と、成果物のSHA-256 | MicroVMのVMM、jailer、スナップショットのAPI |
| [Raft](https://raft.github.io/raft.pdf) | 拡張版の論文 | 合意プロトコル |

## 設計の由来

[SecCamp-AIAgentのコミット`9e8355b`](https://github.com/Aqua-218/SecCamp-AIAgent/tree/9e8355b7af8e38d17b5bc55c8c85652f39cba95e)を、[5.8](node/runtime.md#sec-5-8)と[8.7](verification/testing.md#sec-8-7)の設計の参考にした。参考にしたのは次の点である。

- ランタイムのライフサイクル
- ホストとの隔離
- スナップショットのidentity
- 上限付きのプロトコル
- 検証のレベル

このリポジトリのコードは、本番の依存にしない。設計の原則として、RubernetesのRuby実装と形式仕様に取り入れる。

upstreamのアルゴリズムをRubyへ移植した箇所の移植元とライセンスは、リポジトリ直下の`NOTICE`に記載する。

## 参照の優先順位

Kubernetes v1.36.2の外部から観測できる挙動と本文が食い違う場合は、互換な挙動を優先する。本文とコーパスを、同じ変更の中で修正する。ただし、[1.3](foundation/goals-and-compatibility.md#sec-1-3)に示したLinuxプラットフォームの境界は除く。

ビルドの入力には、参照先のブランチの先頭や`latest`を使わない。タグ、コミット、ディスクリプタのダイジェスト、成果物のダイジェストを、ロックファイルに固定する。

機械可読な固定値は、[`third_party/locks/`](../third_party/locks/README.md)を正本とする。本文とロックが食い違う場合は、実行を止める。両方を同じ変更の中で修正する。

## 関連

- [文書規約](foundation/document-conventions.md)
- [目的と互換性](foundation/goals-and-compatibility.md)
- [検証の目次](verification/README.md)
- [Kubernetes互換性試験](verification/kubernetes-compatibility.md)
