[仕様書の目次](README.md)

<a id="sec-12"></a>
# 12. 規範参照と設計の由来

> 対象読者: すべての実装者、検証者、仕様編集者
>
> 状態: 規範、版0.2

固定する外部仕様、compatibility oracle、設計由来、参照優先順位を定義する。


| 参照 | 固定対象 | 本書での役割 |
|---|---|---|
| [Ruby 3.4.11](https://www.ruby-lang.org/en/news/2026/09/23/ruby-3-4-11-released/) | source SHA-256 `5c22be44524312b3d433d68739bcc530633b1da5ef8ba0afa0a37680da17d3de` | development/CI runtime、Ruby API・ABI baseline |
| [Kubernetes](https://github.com/kubernetes/kubernetes/tree/v1.36.2) | tag `v1.36.2` | API、controller、scheduler、node の互換 oracle |
| [Kubernetes Conformance](https://github.com/kubernetes/kubernetes/blob/v1.36.2/test/conformance/testdata/conformance.yaml) | 446件、SHA-256 `cdbad746df8e8f5f7e63ef147b579e921c1ad70a68d826f2b9c5af27dbbf7641` | release 適合試験 |
| [CNCF Conformance instructions](https://github.com/cncf/k8s-conformance/blob/691d9b951a75accf18dfc29b811a3947db874081/instructions.md) | commit `691d9b951a75accf18dfc29b811a3947db874081`、file SHA-256 `77c5bc20e5702497ee82db64a6c9115862709974921ffea8d46230e92462c18e` | skipなしの提出形式とrequired evidence |
| [Hydrophone](https://github.com/kubernetes-sigs/hydrophone/tree/v0.7.0) | tag `v0.7.0`、commit `3de3e886a2f6f09635d8b981c195490af1584d97` | direct Conformance runner |
| [Sonobuoy](https://github.com/vmware-tanzu/sonobuoy/tree/v0.57.5) | tag `v0.57.5`、commit `310c51d9874a4d10d021ec8a19f8b42292ec0bfc` | CNCF形式のConformance evidence |
| [Kubernetes version-skew policy](https://kubernetes.io/releases/version-skew-policy/) | 2026-08-22取得 | kubectl/client component test matrix |
| [Kubernetes large cluster limits](https://kubernetes.io/docs/setup/best-practices/cluster-large/) | v1.36 documentation | [§1.5](foundation/goals-and-compatibility.md#sec-1-5) の規模上限 |
| [OCI Image Spec](https://github.com/opencontainers/image-spec/tree/v1.1.1) | tag `v1.1.1` | image manifest、config、layer |
| [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec/tree/v1.1.1) | tag `v1.1.1` | registry protocol |
| [Linux UAPI](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/?h=v6.12) | tag `v6.12` | syscall number、flag、struct layout |
| [Firecracker](https://github.com/firecracker-microvm/firecracker/tree/v1.16.1) | tag `v1.16.1` と artifact SHA-256 | MicroVM VMM、jailer、snapshot API |
| [Raft](https://raft.github.io/raft.pdf) | extended paper | 合意 protocol |

[SecCamp-AIAgent commit `9e8355b`](https://github.com/Aqua-218/SecCamp-AIAgent/tree/9e8355b7af8e38d17b5bc55c8c85652f39cba95e)
の runtime lifecycle、host isolation、snapshot identity、bounded protocol、verification level を
[§5.8](node/runtime.md#sec-5-8) と [§8.7](verification/testing.md#sec-8-7) の設計参考とした。同 repository の code は production dependency にせず、
Rubernetes の Ruby 実装と形式仕様へ設計原則として移植する。

Kubernetes v1.36.2 の外部観測可能な挙動と本文が衝突した場合は、[§1.3](foundation/goals-and-compatibility.md#sec-1-3) の Linux platform 境界を除き、
互換挙動を優先して本文と corpus を同じ変更で修正する。reference の branch head や `latest` を
build 入力に用いず、tag、commit、descriptor digest、artifact digest を lock file に固定する。
machine-readableな固定値は[`third_party/locks/`](../third_party/locks/README.md)を正本とし、
本文とlockが衝突した場合はrunを停止して両方を同一変更で修正する。

## Related

- [document conventions](foundation/document-conventions.md)
- [goals and compatibility](foundation/goals-and-compatibility.md)
- [Verification index](verification/README.md)
- [Kubernetes compatibility](verification/kubernetes-compatibility.md)
