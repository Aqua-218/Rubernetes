[仕様書の目次](../README.md) / [検証](README.md)

<a id="sec-7"></a>
# 7. 形式仕様

> 対象読者: 形式検証の担当者、ランタイムと分散システムの実装者、審査者
>
> 状態: 規範、版0.2

TLA+、Lean、実行時検証のそれぞれの役割を定義する。あわせて、定理、禁止事項、保証レベルの台帳を定める。


> **Diagram:** [図 08 — Verification](../diagrams/08-verification.md)

<a id="sec-7-1"></a>
## 7.1 分担

| 手法 | 対象 | 根拠 |
|---|---|---|
| TLA+ | 並行・分散・時相性質 | 複数プロセスの相互作用と活性は状態探索でしか扱えない |
| Lean | 純関数のロジック | 全 domain に対する定理は有界探索では得られない |
| 実行時検証 | 実装と仕様の乖離 | 形式仕様は実装を直接には縛らない |

<a id="sec-7-2"></a>
## 7.2 TLA+ で記述するもの

| 仕様 | 不変条件 | 活性 |
|---|---|---|
| Raft | ElectionSafety、LeaderAppendOnly、LogMatching、LeaderCompleteness、StateMachineSafety | リーダーが最終的に選出される。分断回復後に収束する |
| 制御ループ | Pod 数が上限を超えない、二重スケジュールしない、孤児が残らない | actual が desired に到達する |
| Runtime | live owner が持つ資源を解放しない、identity を再利用しない、Unknown から実行しない、rollback は逆順 | cleanup failure 解消後に `Stopped` または `Removed` へ到達する |
| Snapshot | pause 不明状態を resume しない、復元 identity と secret が元状態と重複しない | 新 identity の ACK 後にだけ workload を開始できる |
| Watch | revision 順序を逆転しない、同一開始点の watcher が同じ列を観測する | compaction がなければ event または bookmark が到達する |

TLC の必須最小探索スコープは controller desired replicas 0〜5、runtime resource 6 種、
各 effect point で success/fail/response-loss の 3 分岐とする。対称性除去前の全状態を `.cfg` と
CI artifact に記録する。より小さい smoke scope を毎コミットで使ってよいが、release gate はこの
最小値を下回ってはならない。

**Raft は TLC の必須対象から除外する。** 2026-09-06 に 3 node、term 0〜4、log 長 0〜5、client 2 で
実測したところ、4 時間で到達状態 12.1 億・キュー 7.9 億・状態ファイル 133 GB に達してなお増加中であり、
網羅探索は完了しない。原因は Raft の状態空間の大きさであってモデルの記述ではない（メッセージ表現の
最適化と履歴変数の有界化による改善は約 2 割にとどまった）。Raft の安全性主張は
`verification/claims.yml` で `integration_tested` として記録し、決定的な障害注入シミュレーションと
M5 プローブを根拠とする。`LogMatching` の全 domain に対する主張は Lean 4 の証明が支える。

<a id="sec-7-3"></a>
## 7.3 Lean で証明するもの

| 対象 | 命題 | 偽なら何が壊れるか |
|---|---|---|
| Raft ログ演算 | LogMatching が全ログ長で成立 | コミット済みデータが失われる |
| seccomp コンパイラ | `⟦compile p⟧ = ⟦p⟧` | 意図しない syscall が通る／必要な syscall が塞がる |
| IPAM | 払い出し IP が重複しない | 2 つの Pod が同一 IP を持ち通信が壊れる |
| OverlayFS 合成 | 合成が結合的、上書き順序が正しい | イメージ層の内容が誤って見える |
| Scheduler | Filter が全域、Score が決定的 | スケジュール結果が再現せず解析不能になる |
| cgroup 階層 | 制限が単調に伝播する | 子が親の上限を超える |
| schema compiler | schema field 集合と Ruby/RBS/codec/OpenAPI/patch field 集合が一致 | API の一部だけが欠落または異なる意味になる |
| rollback planner | dependency DAG の逆 topological order だけを返す | live owner より先に下位資源を解放する |
| snapshot identity | 旧 identity set と復元 identity set が disjoint | token、nonce、IP、workspace が clone 間で再利用される |
| bounded framing | length check 後の allocation が上限以下 | 不正 peer が host memory を枯渇させる |

各定理には「偽なら何が壊れるか」を必ず付す。
書けない命題は証明しない。守っている対象がないため。

Lean から得た executable reference は test oracle としてだけ使用する。本番処理を Lean 抽出コードへ
委譲せず、Ruby 実装へ同じ入力を与える differential property test で対応付ける。

<a id="sec-7-4"></a>
## 7.4 証明の強度

| 分類 | 扱い |
|---|---|
| `rfl` で閉じるもの | `theorem` としない。`example` に留める |
| 全域性・決定性 | 補題として扱う。単体では成果としない |
| 帰納法・場合分けを要するもの | 定理として数える |
| 全称量化が本質的なもの | 主要成果とする |

<a id="sec-7-5"></a>
## 7.5 禁止事項

- `sorry`、`admit` の使用
- `native_decide` による証明の閉じ
- 仮定を追加して命題を弱めること（追加する場合は理由を明記し、記録に残す）

CI で機械的に検出する。

<a id="sec-7-6"></a>
## 7.6 証明が実装を縛っていることの確認

証明が空回りしていないことを、変異検査で確認する。
実装に意図的な欠陥を入れ、対応する定理または検証が
実際に失敗することを確かめる。失敗しない場合、その証明は無効とみなす。

<a id="sec-7-7"></a>
## 7.7 保証レベル台帳

各安全主張は `verification/claims.yml` に ID、対象、前提、TCB、手法、反例、対応 test、
対応実装 path を記録する。保証レベルは次のいずれか 1 つとし、より強い表現へ読み替えてはならない。

| level | 意味 |
|---|---|
| `proved` | Lean で全称量化された定理を `sorry` なしで証明 |
| `model_checked` | 明記した有限 scope で TLA+/TLC が反例なし |
| `differentially_tested` | 固定 oracle corpus と観測結果が一致 |
| `integration_tested` | 実 kernel/KVM 上の境界を検査 |
| `assumed_tcb` | kernel、KVM、CPU、Firecracker 等へ置いた仮定 |

VM escape 耐性、host kernel/KVM/CPU の正しさ、全 syscall 実装の正しさは `assumed_tcb` とする。

## Related

- [testing](testing.md)
- [raft](../control-plane/raft.md)
- [runtime](../node/runtime.md)
- [08 verification](../diagrams/08-verification.md)
