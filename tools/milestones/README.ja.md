# マイルストーンのプローブとゲート

[English](README.md) | 日本語

検証を担当する人とレビュアに向けた文書です。

## 仕組み

マイルストーンはM0からM9まであります。各マイルストーンは次の2段階で完了を判定します。

1. `rake m<n>:evidence`が検査を実行し、結果を証拠バンドルにまとめます。バンドルは`artifacts/milestones/M<n>/<run-id>/`に置かれ、内容のダイジェストで識別されます。
2. `rake m<n>:verify`がゲートとしてバンドルを再検査します。

バンドルが`COMPLETE`になるのは、次の条件をすべて満たしたときだけです。

- 取得中にソース一覧のダイジェストが変わらなかった。
- 必要な実アダプタと外部ランナーがすべて動いた。
- 参照する前段のバンドルが同じソースから取得されている。

アダプタの欠落、テストのスキップ、取得中のソース変更があった場合、バンドルは`INCOMPLETE`として記録されます。`INCOMPLETE`のバンドルが合格になることはありません。なお、ここにあるツールはGitリポジトリを必要とせず、作成もしません。

## ゲートの連鎖

ゲートは前段の結果に依存します。`rake m1:verify`は`COMPLETE`なM0のマニフェストを要求し、M2はM1を要求します。M9まで同じ関係が続きます。前段のマニフェストは環境変数で渡してください。

```bash
rake m0:evidence
RUBERNETES_M1_M0_MANIFEST=artifacts/milestones/M0/<run-id>/manifest.json rake m1:verify
RUBERNETES_M2_M1_MANIFEST=artifacts/milestones/M1/<run-id>/manifest.json rake m2:verify
RUBERNETES_M3_M2_MANIFEST=artifacts/milestones/M2/<run-id>/manifest.json rake m3:verify
RUBERNETES_M4_M3_MANIFEST=artifacts/milestones/M3/<run-id>/manifest.json rake m4:verify
RUBERNETES_M5_M4_MANIFEST=artifacts/milestones/M4/<run-id>/manifest.json rake m5:verify
RUBERNETES_M6_M5_MANIFEST=artifacts/milestones/M5/<run-id>/manifest.json rake m6:verify
RUBERNETES_M7_M6_MANIFEST=artifacts/milestones/M6/<run-id>/manifest.json rake m7:verify
RUBERNETES_M9_M8_MANIFEST=artifacts/milestones/M8/<run-id>/manifest.json rake m9:verify
```

ソースを変更するとダイジェストが変わり、取得済みのバンドルはすべて無効になります。その場合はM0から取り直してください。

以下、各ゲートが何を要求するかを順に説明します。

## M0 実行基盤

`rake m0:verify`は次の4つを実行します。

- gemのビルド
- テストスイート
- 各実行ファイルの`--help`と`--version`の確認
- ネイティブ境界のスキャン

`rake m0:kernel`は、特権が必要なx86_64のstage-00カーネルプローブを実行します。

`rake m0:evidence`が`COMPLETE`を報告する条件は2つです。ソースのダイジェストが安定していること、そして同じソースに対して実カーネルプローブが成功していることです。

## M1 スキーマとAPIコア

次の5つの実アダプタを要求します。

| アダプタ | 合格の条件 |
|---|---|
| 生成の再現性 | 生成物がバイト単位で再現できる |
| Kubernetes validationオラクル | 生成した770の型すべてを、実行可能なupstreamのREST strategyに対応付けられる |
| round-tripプローブ | 不一致がゼロ |
| API differential | 固定したkube-apiserverとetcdを相手に、必須の22操作がすべて一致する |
| kubectlプローブ | kubectlからの操作が通る |

API differentialの22操作には、TokenReview、SelfSubjectReview、SelfSubjectRulesReview、SubjectAccessReview、ComponentStatus、Podのevictionが含まれます。

## M2 Native Pod

ゲートは次の5つを要求します。

- x86_64のRuntime L0〜L3プロファイル
- OCI攻撃コーパス
- ライフサイクルのトレース
- 1,000サイクル分のリソース台帳
- カーネルオブジェクトの一覧

Podライフサイクルの観測値は、本物のKubernetes v1.36.2ノードと比較します。比較する項目は、initコンテナの順序、probeの閾値、再起動のバックオフ、graceful terminationです。比較相手のノードには、固定したソースからビルドしたkindノードイメージを使います。

RuntimeLifecycleの形式的な主張は、本番のNativeランタイムが書いた所有権ジャーナルから再生したトレースで判定します。ジャーナルはハッシュで連鎖しています。判定にはRubyのトレース検証器、TLC、Apalache、Leanを使います。検査の条件は`verification/proof-profile.json`に固定してあり、`tools/verification/m2_proof_profile.rb`が読み込みます。

`rake m2:kernel`で実カーネルアダプタを実行できます。ARM対応は任意で、ゲートの前提条件には含みません。

## M3 制御ループ

3種類の検査があります。

ワークロードのdifferentialは20ケースです。Deployment、StatefulSet、DaemonSet、Job、CronJobのそれぞれについて、rollout、rollback、scale、deleteを試します。本番のControllerManagerServiceの結果を、固定したkube-controller-managerの結果と比べます。

スケジューラのdifferentialは、固定したkube-schedulerと結果が一致することを確かめます。

カオスランナーは、リーダーの喪失とqueue・informerの障害を起こします。プロセスが実際に入れ替わったあとでLeaseが引き継がれることを確認します。

## M4 ワークロードデータプレーン

データプレーンのプローブは、どれも独立した外部ランナーを必要とします。

| ランナー | 内容 |
|---|---|
| ボリューム観測とクラッシュ | private mount namespaceで動かす。効果の境界ごとにSIGKILLを送り、スナップショットの整合性を確かめる |
| CSIプラグインオラクル | Goで書いたCSIプラグイン。本番のCSIクライアントがgRPCで駆動する |
| マウント攻撃観測 | マウントへの攻撃を観測する |
| ネットワーク観測 | ゲートが動いている間、ネットワーク名前空間とパケットキャプチャを保持する |
| NetworkPolicyオラクル | 固定したkindノードイメージを起動する。kindnetdによるポリシー強制を有効にする |
| プロキシparity | eBPFとnftablesの両データパスでコーパス41件がすべて一致する。バックエンド切替時の接続断がゼロ |

`rake m4:evidence`を実行する前に、ランナーのコマンドを環境変数にexportしてください。

```bash
RUBERNETES_M4_VOLUME_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode observation"
RUBERNETES_M4_SNAPSHOT_RECOVERY_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode crash"
RUBERNETES_M4_CSI_ORACLE_COMMAND="ruby test/conformance/kubernetes/m4_csi_oracle/runner.rb"
RUBERNETES_M4_MOUNT_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode observation"
RUBERNETES_M4_NETWORK_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_network_observation/runner.rb"
RUBERNETES_M4_NETWORK_POLICY_ORACLE_COMMAND="ruby test/conformance/kubernetes/m4_policy_oracle/runner.rb"
RUBERNETES_M4_KERNEL_WAIVER_REASON="<owner-granted reason>"
```

ネットワーク観測ランナーは、観測した名前空間を保持するデーモンを残します。ゲートが終わったら`runner.rb --reap`を実行してください。デーモンを停止し、止まらなければ強制終了し、残ったホスト側のリンクを削除します。

### カーネルの免除

M4のゲートは、SCTP CRC32cヘルパの検査のためにLinux 6.12以降を期待します。M4を取得した2026-09-04の時点で、開発ホストはそのカーネルで再起動できませんでした。そこでプロジェクトオーナーがこの要件を免除しています。

免除の理由は`RUBERNETES_M4_KERNEL_WAIVER_REASON`で渡します。理由はM4マニフェストの`waivers`に記録され、ゲートの出力にも表示されます。6.12専用のヘルパに依存しない検査は、すべて古いカーネル上で実行済みです。

## M5 耐久性と高可用性

5つのプローブがあります。

### m5_linearizability_probe.rb

本番のRaftノードを決定的シミュレーションで動かします。注入する障害は、分断、非対称な分断、並べ替え、重複、欠落、クラッシュと再起動、時刻のジャンプです。すべてのクライアント履歴を`tools/verification/linearizability.rb`で検査します。検査に使うRubyの逐次モデルは、先にLeanの参照モデル`verification/lean/KVSequential.lean`と比較しておきます。

### m5_fault_matrix_probe.rb

実際のworkerプロセスをTLS上で動かし、書き込みのackが返っている最中に障害を起こします。

- 3台構成で1台、5台構成で2台をSIGKILLする。
- joint consensusによるメンバー変更の最中にリーダーを停止する。
- スナップショットのinstall中にリーダーを停止する。

どの場合も、コミットの喪失がゼロ、split brainがゼロ、再起動後にレプリカが一致することを要求します。

### m5_corruption_probe.rb

実際のWALとスナップショットを破壊します。破壊の種類は、ビット反転、末尾の欠落、ゼロ埋めされた末尾、過大な長さ、切り詰めです。さらに、サイズを制限したtmpfsを満杯にしてENOSPCを起こし、short writeとfsyncの失敗も注入します。

すべてのケースで、プロセスが安全側に停止し、ack済みの範囲のデータが残ることを要求します。バックアップのround-tripと、改竄したバックアップの拒否も確認します。

### m5_rto_rpo_probe.rb

Raftデータストアの上で、本物の`rubernetes-apiserver`を3プロセスと本物のcontroller managerを起動します。そのうえでAPIサーバを2台停止し、次の点を確かめます。

- 停止中は書き込みにackが返らず、`/readyz`が失敗する。
- quorumを回復すると読み書きとDeploymentの制御ループが再開する。再開までの時間は60秒以内。
- 失われるオブジェクトは0件。

### m5_ownership_probe.rb

耐久性のある効果ジャーナルをすべて対象にします。Raftストア、Nativeランタイム、コントローラ、ボリューム、ネットワークの5つです。効果の前と後のそれぞれでクラッシュさせ、ジャーナルを再生します。要求の喪失と応答の喪失を区別して記録したうえで、各効果がちょうど1回だけ再実行されることを要求します。

## M6 完全なAPI

6つのプローブがあります。

### m6_api_coverage_probe.rb

提供しているdiscovery文書、verb、OpenAPI v3の操作、protobufのディスクリプタを、固定したコーパスと比較します。欠落がゼロであることを要求します。

### m6_feature_gate_probe.rb

提供しているAPIを、基準のkube-apiserverから取得したdiscoveryと比較します。比較するプロファイルは、既定、`AllBeta=true`、alpha APIの3つです。差分がゼロであることを要求します。

### m6_crd_differential_probe.rb

CRDとaggregationを扱う1本のスクリプトを、Docker内の固定したkube-apiserverと本番サーバの両方で実行します。正規化した観測結果が一致することを要求します。スクリプトが扱う項目は次のとおりです。

- structural validationのメッセージ
- defaultingとpruning
- 複数バージョンの提供
- statusサブリソース
- OpenAPIの公開
- APIServiceの可用性
- cleanup finalizer

### m6_webhook_differential_probe.rb

同じadmission webhookを両方のサーバに登録し、結果が一致することを要求します。確かめる項目は次のとおりです。

- FailとIgnoreの各ポリシーでのタイムアウト
- mutationとwarning
- reinvocation policy、match policy、match condition
- AdmissionReviewのバージョン交渉
- dry-runでの副作用
- object selector

### m6_security_pipeline_probe.rb

本番のリクエスト処理パイプラインについて、段階の順序を記録します。エラーの開示も検査します。401、403、404の順で判定されること、内部の詳細が漏れないこと、すべての結果が監査に残ることを確かめます。

### m6_fuzz_probe.rb

不正な入力、過大な入力、重複したキー、パス、content negotiationの入力を投入します。seedを指定すれば同じ入力を再現できます。panic、ハング、ポリシーの回避がゼロであることを要求します。

## M7 MicroVM分離

ゲストの成果物は`rake m7:artifacts`でビルドします。実体は`tools/microvm/build_guest_kernel.sh`と`tools/microvm/build_guest_artifacts.rb`です。ビルド結果は`third_party/locks/m7-microvm-artifacts.json`に固定します。プローブは本物のKVMホストで動かしてください。

### m7_kvm_probe.rb

L4とL5のレポートを作ります。検査する内容は次の4つです。

- 成果物の検証
- コールドブートと復元の両方でのPodライフサイクル。exec、logs、stats、probe、ネットワークを確かめ、閉じ込めをカーネル側で検証する。
- multiplexer経由での`Node::Lifecycle` APIの契約
- 障害マトリクス。jailerのkill、VMMのハング、UDSの切断、vsockの切断、pause ACKの喪失を起こす。

どの障害でも、安全側に停止し、残骸が残らないことを要求します。

### m7_attack_probe.rb

動いているゲストから攻撃を試みます。対象は、jailerのroot、ホストのファイルシステム、他のVMのvsock、未登録のホストポート、他テナントのネットワーク、自身のrootfsです。偽造したACK、古いACK、未知のbroker操作が拒否されることも確かめます。restrictedクラスのVMにNICがないことも確認します。

### m7_identity_probe.rb

1つのベーススナップショットから8つのクローンを作ります。ローテートされるidentityフィールドが、クローン間でも台帳の履歴の中でも重複しないことを要求します。古いACKと失効したcapabilityが拒否されることも確かめます。

### m7_snapshot_probe.rb

スナップショットを破壊するコーパスを使います。破壊の種類は、ビット反転、切り詰め、再署名したゴミデータ、成果物の不一致、ファイルの欠落です。壊れたベースからVMが起動しないことを要求します。

### m7_latency_probe.rb

キャッシュ済みのベースからPodを起動し、所要時間の生サンプルを記録します。p95が1.5秒以下であることを要求します。

## M8 Kubernetes互換性

`tools/conformance/run.rb`が、[互換性の試験契約](../../spec/verification/kubernetes-compatibility.md)にあるK0〜K7の検査を実行します。結果はプロファイルごとの実行マニフェストに書き出されます。

前提条件が欠けている検査は、理由を付けて`INCOMPLETE`を報告します。モックで代用したり、ほかの実行の結果を流用したりはしません。M8のゲートは`INCOMPLETE`の検査があると不合格にします。

| コマンド | 役割 |
|---|---|
| `rake m8:lanes` | 検査を実行する |
| `rake m8:evidence` | バンドルを取得する |
| `rake m8:verify` | ゲートを実行する |

クラスタの起動と日常のconformance実行については、[tools/conformance](../conformance/README.ja.md)を読んでください。

## M9 リリース

`tools/release/` がリリース証拠を作ります: `sbom.rb`（CycloneDX 1.5、決定的）、
`release_manifest.rb`（ソースインベントリのダイジェストを束ねる）、
`loc_report.rb`（ネイティブ拡張を含めた Ruby 比率）、`reproduce.rb`（バイト一致の
再ビルド）、`security_report.rb`（advisory、未固定入力、主張レベル、日付なし
マーカー）、`benchmark.rb`（Kubernetes v1.36.2 オラクルとの比較）、`soak.rb`
（72 時間、追記専用ジャーナル）。72 時間未満の soak、オラクルなしのベンチ
マーク、クリーンホストでの再現欠落は、合格ではなく未達として報告されます。
`rake m9:artifacts` が成果物を生成し、`rake m9:verify` がゲートします。

## 履歴

- 2026-09-04: 独立した監査で、2026-08-23 の `COMPLETE` バンドルが当時のゲートに
  拒否されることが判明。2026-09-04/05 に M1〜M4 のオラクル、プローブ、ゲート契約を
  修復し（リストエンベロープからの TypeMeta 復元、status サブリソースの
  ジャーナリング、効果チェックポイントの束縛、台帳サイクル種別、オラクルの stdin
  束縛、観測ダイジェスト、カオス回復記録の形、全マイルストーン共通の生成器
  一時ディレクトリ除外）、M0 → M4 の連鎖を 1 つのソース identity で取り直し、
  全マニフェストが `COMPLETE` に。不安定だった 2 つの計測は再試行ではなく
  決定的にした: L3 ランタイムスモークは既に終了した短命ワークロードに対する
  `pidfd_open` の EINVAL を文書化された終了レースとして扱い、graceful-termination
  オラクルは「猶予期間後に kill された」を秒精度の API タイムスタンプではなく
  ハーネスが測った delete→DELETED 間隔から導出する。
- 2026-09-06/07: M5、M6、M7 のプローブとゲートが入り、2026-09-05 の M4 バンドルの
  上に M5〜M7 の連鎖を取得。
- 2026-09-30: リポジトリ全体の RuboCop 整形の後、新しいツリーで M0/M1 のゲートと
  プローブを再実行し clean。ソース変更前に取得したバンドルは設計上 stale で
  あり、リリース候補では連鎖全体を取り直す。

## 関連

- [マイルストーンと完了ゲート](../../spec/delivery/milestones.md)
- [検証戦略](../../spec/verification/testing.md)
- [形式検証ソース](../../verification/README.md)
