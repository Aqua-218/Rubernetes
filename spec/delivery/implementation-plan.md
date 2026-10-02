[仕様書の目次](../README.md) / [実装と納品](README.md)

<a id="sec-9"></a>
# 9. 実装順

> 対象読者: 実装者、プロジェクトの管理者、審査者
>
> 状態: 規範、版0.3

すべてのMUST要件を完成させるための実装順、確定済みの設計判断、リリースゲートを定義する。

段階は実装の順序だけを表す。最終的なスコープを分割したり、任意にしたりするものではない。各段階が終わった時点で、それまでに作った縦割りの機能、生成物、形式仕様、回帰テストが同時に動く状態を保つ。

[マイルストーン](milestones.md)は、ここで定めるstageをM0〜M9にまとめたものである。マイルストーンの文書は、各境界での成果物、完了条件、機械可読な証拠を追加で定義する。2つの文書が食い違う場合は、より厳しい完了条件を適用する。

| 段階 | 到達点 | 主な検証 |
|---|---|---|
| 00 | RubyのFFI、ABIの生成器、機能のプローブ（clone3、pidfd、mount、netlink、bpf、KVM） | x86_64の実kernelでのスモークテスト |
| 01 | v1.36.2のコーパス、スキーマDSLとコンパイラ、Rubyの型、コーデック、OpenAPI、RBS、Manifest DSL | 再生成の差分がゼロ、全GVKのround-trip |
| 02 | APIサーバとMemoryStore、discovery、CRUD、watch、patch、apply | `kubectl`と、APIの差分テスト |
| 03 | Nativeのサンドボックス、イメージ、namespace、OverlayFS、cgroup、seccomp、プロセスのgate | ランタイムのL0〜L3、資源のリークがゼロ |
| 04 | ノードエージェントと、1ノードでのPodライフサイクルの一貫した動作 | initコンテナ、sidecar、probe、再起動、終了のe2e |
| 05 | Controller DSL、DeploymentからReplicaSet、Podまで | 冪等性、所有関係、rolloutの差分テスト |
| 06 | informerと、v1.36.2の組み込みコントローラの全体 | イベントの欠落、全コントローラのコーパスへの登録 |
| 07 | Scheduler DSL、すべての標準プラグイン、preemption、複数ノード | FilterとScoreのLeanによる証明、配置の差分テスト |
| 08 | Nativeのネットワーク、IPAM、VXLAN、NetworkPolicy、DNS、eBPFとnftablesのプロキシ | Pod、Service、Ingress、Egressのe2e |
| 09 | ボリューム、PV・PVC・StorageClass、スナップショット、CSIプロトコル | マウントへの攻撃、attachのレース、ストレージのe2e |
| 10 | RaftStore、WAL、スナップショット、メンバーシップ | TLA+、クラッシュからの回復、線形化可能性 |
| 11 | すべての認証、認可、admission、CRD、aggregation、すべてのAPIとsubresource | v1.36.2のAPIコーパスとの差分がゼロ |
| 12 | Firecrackerとjailer、Ruby製のゲストsupervisor、標準とrestrictedのMicroVM | ランタイムのL0〜L5、identityを再利用しないこと |
| 13 | すべてのコンポーネントの耐久性のある所有権、ロールバック、クラッシュからの回復 | すべてのeffect pointの障害の組み合わせ |
| 14 | Conformance、HelmとOperatorのコーパス、障害注入のDSL、トレース・モデル・証明の対応付け | 改変していないupstreamのテスト、反例の固定 |
| 15 | 性能、長時間の試験、供給網の固定、リリースの成果物 | [9.3](implementation-plan.md#sec-9-3)のリリースゲートの全項目 |

<a id="sec-9-1"></a>
## 9.1 段階00の完了条件

- Rubyから`clone3(2)`をFFI経由で呼べる。`CLONE_NEWPID | CLONE_NEWNS | CLONE_PIDFD`を指定できる。
- 子プロセスの中で`/proc`をマウントし直すと、`ps`が自分のプロセスだけを表示する。
- 親がpidfdで子の終了を待てる。PIDの再利用と混同せずに、終了コードを取得できる。
- 失敗したときに、`errno`を正しく取得できる。
- x86_64の構造体のサイズ、アラインメント、システムコール番号を、kernelのヘッダから作ったマニフェストと照合できる。
- netlinkのACK、BPF verifierのログ、`/dev/kvm`の機能を、Rubyから取得できる。

この段階を通過できなければ、以降の設計は成立しない。最優先で確認する。

<a id="sec-9-2"></a>
## 9.2 確定済みの設計判断

| ID | 決定 |
|---|---|
| D1 | user namespaceは、`hostUsers=false`のPodの単位で共有する。既定の`hostUsers=true`では、Kubernetesとの互換を保つ |
| D2 | Raftのバッチは、256エントリ、1 MiB、2 msとする。スナップショットは、100,000エントリまたはWAL 512 MiBで取る |
| D3 | プロキシはeBPFとnftablesの両方のbackendを実装する。機能のプローブで自動的に選ぶ |
| D4 | Leanから抽出したコードはテストの基準に限定する。本番のRuby実装とは、差分のproperty testで結び付ける |
| D5 | CRD、動的な登録、conversion、OpenAPIの公開は、リリースの必須要件とする |
| D6 | Nativeを既定とする。MicroVMとMicroVMRestrictedを標準のRuntimeClassとする |
| D7 | rootlessは、user namespaceと専用のhelperによる最小特権の分離として実装する。特権が必要な処理をagent本体に置かない |

<a id="sec-9-3"></a>
## 9.3 リリースの完了条件

次のすべての項目を満たすまで、`1.0.0`、完成、完全互換を名乗ってはならない。

- v1.36.2のdiscovery、OpenAPI、protobuf、APIの挙動のコーパスに対して、未実装の項目が0である。
- upstreamのv1.36.2のLinux Conformance 446件で、失敗とスキップが0である。再試行でしか成功しないflakyなテストも0である。
- プラットフォームの許可リストにないスキップが0である。
- Native、MicroVM、MicroVMRestrictedが、それぞれ対応するランタイムのL0〜L5のゲートを通過している。
- 組み込みのコントローラ、スケジューラのプラグイン、CRD、CSI、NetworkPolicy、eBPFとnftablesのプロキシが、e2eを通過している。
- すべてのeffect pointでクラッシュと応答の喪失を注入しても、動いている資源の誤った解放と、identityの再利用が0である。
- TLA+のリリース用スコープで反例が0である。Leanの`sorry`、`admit`、禁止した抜け道が0である。
- スキーマの生成の差分が0である。RBS、OpenAPI、コーデック、patchのフィールドの集合に不一致がない。
- 互換性コーパスのHelm chartとOperatorを、変更せずにinstall、upgrade、rollback、uninstallできる。
- [Kubernetes互換性試験契約](../verification/kubernetes-compatibility.md)のK0〜K7を、すべてのプロファイルで通過している。
- プロジェクトが書いた本番ソースのうち、Rubyの比率が85%以上である。
- 未決のマーカー、期限のない作業メモ、保証レベルが書かれていないセキュリティ上の主張が0である。

## 関連

- [コーディング規約](coding-standards.md)
- [マイルストーン](milestones.md)
- [プロジェクト構成](project-structure.md)
- [目的と互換性](../foundation/goals-and-compatibility.md)
- [Kubernetes互換性試験](../verification/kubernetes-compatibility.md)
