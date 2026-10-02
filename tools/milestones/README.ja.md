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

`rake m0:verify` は gem ビルド、テストスイート、実行ファイルの help/version
プローブ、ネイティブ境界スキャンを実行し、`rake m0:kernel` は特権付きの x86_64
stage-00 カーネルプローブを実行します。`rake m0:evidence` は、ソース入力の
ダイジェストが安定し、同じ入力に対して実カーネルプローブが成功したときだけ
`COMPLETE` を報告します。

## M1 スキーマと API コア

5 つの実アダプタ: 生成の再現性、Kubernetes validation オラクル（生成した全型
770/770 を実行可能な upstream REST strategy に対応付け）、round-trip プローブ
（不一致ゼロ）、固定した kube-apiserver/etcd に対する API differential
（TokenReview、SelfSubjectReview、SelfSubjectRulesReview、SubjectAccessReview、
ComponentStatus、Pod eviction を含む必須 22 操作すべて）、kubectl プローブ。

## M2 Native Pod

ゲートは x86_64 の Runtime L0〜L3 プロファイル、OCI 攻撃コーパス、ライフ
サイクルトレース、1,000 サイクルのリソース台帳、カーネルオブジェクト一覧を
要求します。Pod ライフサイクルの観測値（init の順序、probe の閾値、再起動
バックオフ、graceful termination）は本物の Kubernetes v1.36.2 ノードオラクル
（固定ソースからビルドした kind ノードイメージ）と比較します。RuntimeLifecycle
の形式的主張は、本番 Native ランタイムのハッシュ連鎖した所有権ジャーナルから
再生したトレース上で、Ruby トレース検証器、TLC、Apalache、Lean により、
決定的な証明プロファイル `verification/proof-profile.json`
（`tools/verification/m2_proof_profile.rb`）の下で判定します。`rake m2:kernel`
は実カーネルアダプタを実行します。ARM 対応は任意で、前提条件ではありません。

## M3 制御ループ

ワークロード differential は 20 ケースすべて（Deployment、StatefulSet、
DaemonSet、Job、CronJob × rollout/rollback/scale/delete）を本番の
ControllerManagerService で固定した kube-controller-manager と突き合わせ、
スケジューラ differential は固定したスケジューラと一致し、リーダー喪失と
queue/informer のカオスランナーは実プロセス世代での Lease の引き継ぎを
示します。

## M4 ワークロードデータプレーン

すべてのデータプレーンプローブは独立した外部ランナーを必要とします:
ボリューム観測とクラッシュのランナー（private mount namespace、すべての
効果境界での SIGKILL、スナップショット整合性）、本番 CSI クライアントが gRPC で
駆動する Go 製 CSI プラグインオラクル、マウント攻撃観測ランナー、ゲートの間
ライブなネットワーク名前空間とパケットキャプチャを保持するネットワーク観測
ランナー、固定した kind ノードイメージを kindnetd 強制付きで起動する
NetworkPolicy オラクル、プロキシ parity ランナー（eBPF と nftables の両
データパスでコーパス 41/41、バックエンド切替時の接続断ゼロ）。ランナーの
コマンドは `rake m4:evidence` の前に export します。

```bash
RUBERNETES_M4_VOLUME_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode observation"
RUBERNETES_M4_SNAPSHOT_RECOVERY_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode crash"
RUBERNETES_M4_CSI_ORACLE_COMMAND="ruby test/conformance/kubernetes/m4_csi_oracle/runner.rb"
RUBERNETES_M4_MOUNT_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode observation"
RUBERNETES_M4_NETWORK_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_network_observation/runner.rb"
RUBERNETES_M4_NETWORK_POLICY_ORACLE_COMMAND="ruby test/conformance/kubernetes/m4_policy_oracle/runner.rb"
RUBERNETES_M4_KERNEL_WAIVER_REASON="<owner-granted reason>"
```

ネットワーク観測ランナーは、ゲートのために観測した名前空間を保持する
デーモンを残します。`runner.rb --reap` がそれを停止し、エスカレートし、
孤児となったホストリンクを掃除します。

**カーネル waiver。** M4 ゲートは SCTP CRC32c ヘルパ経路のために Linux >= 6.12
を期待します。M4 取得時（2026-09-04）、開発ホストはそのカーネルに再起動
できず、プロジェクトオーナーがこの要件を免除しました。waiver は
`RUBERNETES_M4_KERNEL_WAIVER_REASON` を通じて M4 マニフェスト（`waivers`）に
明示的に記録され、ゲートも表示します。黙ったスキップではなく、6.12 専用
ヘルパに依存しないものはすべて古いカーネル上で検証しています。

## M5 耐久性のある高可用性

- `m5_linearizability_probe.rb` は本番 Raft ノードを決定的シミュレーション
  （分断、非対称分断、並べ替え、重複、欠落、クラッシュ/再起動、時刻ジャンプ）で
  駆動し、すべてのクライアント履歴を `tools/verification/linearizability.rb` で
  検査します。Ruby の逐次モデルは先に Lean の参照
  `verification/lean/KVSequential.lean` と比較します。
- `m5_fault_matrix_probe.rb` は実 worker プロセスを TLS 上で動かし、書き込みが
  ack されている最中に 3 台中 1 台と 5 台中 2 台を SIGKILL し、joint-consensus の
  メンバー変更中とスナップショット install 中にリーダーを殺し、コミット喪失
  ゼロ、split brain ゼロ、再起動後のレプリカ一致を要求します。
- `m5_corruption_probe.rb` は実 WAL とスナップショットを破壊し（ビット反転、
  切れた末尾とゼロ埋め末尾、過大な長さ、切り詰め）、サイズ制限 tmpfs を満杯に
  して ENOSPC を起こし、short write と fsync 失敗を注入し、すべてのケースで
  fail closed しつつ ack 済みプレフィックスが生き残ることを要求します。
  バックアップの round-trip と改竄バックアップの拒否も確認します。
- `m5_rto_rpo_probe.rb` は Raft データストア上で本物の `rubernetes-apiserver`
  3 プロセスと本物の controller manager を起動し、API サーバ 2 台を殺し、停止中に
  書き込みが ack されず `/readyz` が失敗することを確認し、quorum を回復して
  読み書きと Deployment 制御ループが再開するまでの時間を測ります（上限 60 秒、
  RPO 0 オブジェクト）。
- `m5_ownership_probe.rb` はすべての耐久効果ジャーナル（Raft ストア、Native
  ランタイム、コントローラ、ボリューム、ネットワーク）を効果の前後でのクラッシュ
  後に再生し、request-loss / response-loss の区別を記録したうえでの
  exactly-once 再実行を要求します。

## M6 完全な API 面

- `m6_api_coverage_probe.rb` は提供する全 discovery 文書、verb、OpenAPI v3
  操作、protobuf ディスクリプタを固定コーパスと比較し、欠落ゼロを要求します。
- `m6_feature_gate_probe.rb` は提供する API 面を、default、`AllBeta=true`、alpha
  API の各プロファイルで取得したオラクルの discovery と比較し、差分ゼロを
  要求します。
- `m6_crd_differential_probe.rb` は 1 本の CRD/aggregation スクリプト（structural
  validation メッセージ、defaulting、pruning、複数バージョン提供、status
  サブリソース、OpenAPI 公開、APIService の可用性、cleanup finalizer）を Docker 内の
  固定 kube-apiserver と本番サーバの両方で実行し、正規化した観測の一致を
  要求します。
- `m6_webhook_differential_probe.rb` は同じ admission webhook（Fail/Ignore
  ポリシーのタイムアウト、mutation と warning、reinvocation policy、match policy、
  match condition、AdmissionReview のバージョン交渉、dry-run の副作用、object
  selector）を両サーバに登録し、結果の一致を要求します。
- `m6_security_pipeline_probe.rb` は本番パイプラインの段階順序を記録し、
  エラー開示（401 → 403 → 404 の順、内部詳細なし、全結果の監査）を検査します。
- `m6_fuzz_probe.rb` は不正・過大・重複キー・パス・content negotiation の入力を
  （seed 付きで再現可能に）投入し、panic・ハング・ポリシー回避ゼロを要求します。

## M7 MicroVM 分離

ゲスト成果物は `rake m7:artifacts`（`tools/microvm/build_guest_kernel.sh`、
`tools/microvm/build_guest_artifacts.rb`）でビルドし、
`third_party/locks/m7-microvm-artifacts.json` に固定します。プローブは本物の
KVM ホストで動きます。

- `m7_kvm_probe.rb`（L4/L5 レポート）: 成果物検証、コールドブートと復元の Pod
  ライフサイクル（exec/logs/stats/probes/network とカーネルで検証した閉じ込め）、
  multiplexer 経由の `Node::Lifecycle` API 契約、障害マトリクス（jailer kill、VMM
  ハング、UDS 切断、vsock 切断、pause ACK 喪失）。それぞれ残骸ゼロで fail closed。
- `m7_attack_probe.rb`: ライブなゲストが jailer root、ホストファイルシステム、
  他 VM の vsock、未登録のホストポート、他テナントのネットワーク、自身の rootfs を
  攻撃。偽造・陳腐化した ACK と未知の broker 操作は拒否。restricted クラスには
  NIC がない。
- `m7_identity_probe.rb`: 1 つのベーススナップショットから 8 クローン。ローテート
  される identity フィールドはクローン間と台帳履歴で一意。陳腐化した ACK と
  失効した capability は拒否。
- `m7_snapshot_probe.rb`: スナップショット破壊コーパス（ビット反転、切り詰め、
  再署名したゴミ、成果物不一致、ファイル欠落）。壊れたベースから VM は決して
  起動しない。
- `m7_latency_probe.rb`: キャッシュ済みベースからの Pod 起動の生サンプル。p95 が
  1.5 秒以下であること。

## M8 Kubernetes 互換性

`tools/conformance/run.rb` は
[互換性契約](../../spec/verification/kubernetes-compatibility.md) の K0〜K7
レーンを実行し、プロファイルごとに実行マニフェストを書きます。前提条件が
欠けたレーンは理由付きで `INCOMPLETE` を報告し、モックで代替したり他の実行の
結果を再利用したりはしません。M8 ゲートは `INCOMPLETE` なレーンを拒否します。
`rake m8:lanes` がレーンを実行し、`rake m8:evidence` がバンドルを取得し、
`rake m8:verify` がゲートします。クラスタ起動と日常の conformance ループは
[tools/conformance](../conformance/README.ja.md) を参照。

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
