[仕様書インデックス](../README.md) / [diagrams](README.md)

<a id="sec-a-5"></a>
# A.5 図 05 — Runtime

> **Audience:** Runtime実装者、セキュリティ検証者
>
> **Status:** Normative — version 0.2

Native/MicroVM、ownership、image、namespace、filesystem、cgroup、security、recoveryを示す。

```mermaid
graph TB

IF["Runtime Interface ◇共通 lifecycle<br/>RunSandbox · CreateContainer<br/>StartContainer · Exec · Logs · Stats"]
NATIVE["Native backend ◆Ruby<br/>namespace · cgroup · process"]
MICRO["MicroVM backend ◆Ruby制御<br/>1 Pod = 1 Firecracker"]
RESTRICT["MicroVMRestricted<br/>NICなし · typed broker"]

subgraph LIFE["◤ 状態機械 / resource ownership ◢"]
    L1["<b>Pure validation</b><br/>effect 前に全入力検証"]
    L2["<b>Durable ledger</b><br/>stable identity · owned resource"]
    L3["<b>Workload gate</b><br/>全境界完成まで停止"]
    L4["<b>Reverse rollback</b><br/>依存順の逆で冪等回収"]
    L5["<b>Unknown</b><br/>observe / cleanup のみ"]
end

subgraph FC["◤ Firecracker / jailer ◢"]
    V1["<b>Artifact pin</b><br/>VMM · kernel · rootfs · dm-verity"]
    V2["<b>Jailer</b><br/>専用 UID/GID · ns · cgroup · seccomp"]
    V3["<b>固定 API sequence</b><br/>drive · vsock · net · start"]
    V4["<b>Snapshot identity</b><br/>resume=false · 再生成 · ACK gate"]
    V5["<b>Ruby guest supervisor</b><br/>Pod内 container lifecycle"]
end

IF --> NATIVE --> LIFE
IF --> MICRO --> LIFE
IF --> RESTRICT --> LIFE
LIFE --> SPEC
MICRO --> V1 --> V2 --> V3 --> V4 --> V5
RESTRICT --> V1

subgraph OCI["◤ OCI Image 取得 ◢"]
    I1["<b>参照解決</b><br/>registry/name:tag@digest<br/>デフォルトレジストリ補完"]
    I2["<b>認証</b><br/>token エンドポイント<br/>scope 交渉 · Basic → Bearer"]
    I3["<b>manifest 取得</b><br/>manifest list / index<br/>arch · os で選択"]
    I4["<b>digest 検証</b><br/>sha256 照合<br/>改竄検出"]
    I5["<b>layer 並列取得</b><br/>range request · 再開<br/>gzip / zstd 展開"]
    I6["<b>content-addressable 保存</b><br/>blob ストア · 参照カウント"]
    I7["<b>config 解釈</b><br/>Env · Cmd · Entrypoint<br/>WorkingDir · User · Volumes"]
    I8["<b>署名検証</b><br/>公開鍵での検証 · 信頼ポリシー"]
end

subgraph FS["◤ ファイルシステム構築 ◢"]
    F1["<b>OverlayFS</b><br/>lowerdir 積層 · upperdir · workdir<br/>whiteout · opaque の扱い"]
    F2["<b>mount namespace 分離</b><br/>MS_PRIVATE で伝播遮断"]
    F3["<b>pivot_root</b><br/>新 root へ切替<br/>旧 root の umount"]
    F4["<b>疑似FS 構築</b><br/>/proc · /sys · /dev/pts<br/>/dev/shm · tmpfs"]
    F5["<b>デバイスノード</b><br/>null · zero · random · tty<br/>mknod / bind mount"]
    F6["<b>bind mount</b><br/>volume 反映 · ro 化<br/>MS_REMOUNT で読取専用"]
    F7["<b>masked / readonly paths</b><br/>/proc/kcore 等の遮蔽"]
end

subgraph NS["◤ Namespace 分離 ◢"]
    N1["<b>clone3 / unshare / pidfd</b><br/>フラグ組立<br/>FFI で raw syscall"]
    N2["<b>PID namespace</b><br/>PID 1 の責務<br/>子プロセスの刈取り"]
    N3["<b>mount namespace</b>"]
    N4["<b>network namespace</b><br/>Sandbox 共有<br/>setns で参加"]
    N5["<b>UTS namespace</b><br/>hostname 設定"]
    N6["<b>IPC namespace</b>"]
    N7["<b>user namespace</b><br/>uid_map / gid_map 書込<br/>setgroups deny<br/>rootless 対応"]
    N8["<b>cgroup namespace</b><br/>階層の見え方を制限"]
    N9["<b>setns で参加</b><br/>既存 Sandbox への join"]
end

subgraph CG["◤ cgroup v2 ◢"]
    G1["<b>階層構築</b><br/>QoS → Pod → コンテナ<br/>cgroup.subtree_control"]
    G2["<b>CPU</b><br/>cpu.max quota/period<br/>cpu.weight"]
    G3["<b>Memory</b><br/>memory.max · memory.high<br/>memory.swap.max<br/>OOM イベント購読"]
    G4["<b>IO</b><br/>io.max · io.weight<br/>デバイス毎の指定"]
    G5["<b>PIDs</b><br/>pids.max でフォーク爆弾対策"]
    G6["<b>統計読出</b><br/>cpu.stat · memory.stat<br/>io.stat · PSI"]
    G7["<b>freezer</b><br/>一時停止 · 再開"]
end

subgraph SEC["◤ セキュリティ層 ◢"]
    S1["<b>seccomp-BPF 生成</b><br/>BPF 命令列を自前で組立<br/>syscall 番号表 x86_64 / aarch64<br/>allow · errno · trap · kill"]
    S2["<b>フィルタ最適化</b><br/>番号でのジャンプテーブル化<br/>arch 検査の前置"]
    S3["<b>capabilities</b><br/>bounding · permitted<br/>effective · inheritable · ambient<br/>capset(2)"]
    S4["<b>no_new_privs</b><br/>prctl で昇格禁止"]
    S5["<b>rlimit</b><br/>nofile · nproc · core"]
    S6["<b>apparmor / selinux ラベル</b><br/>プロファイル適用"]
end

subgraph PROC["◤ プロセス生成 ◢"]
    P1["<b>clone3 + PIDFD</b><br/>PID namespace 生成<br/>親子の同期パイプ"]
    P2["<b>同期プロトコル</b><br/>親: uid_map 書込<br/>子: 書込完了を待つ"]
    P3["<b>環境構築</b><br/>環境変数 · cwd · uid/gid<br/>補助グループ"]
    P4["<b>pty 割当</b><br/>openpty · 制御端末設定<br/>TIOCSCTTY"]
    P5["<b>fd 整理</b><br/>不要 fd の close<br/>CLOEXEC 制御"]
    P6["<b>execve</b><br/>Entrypoint + Cmd 合成<br/>PATH 解決"]
    P7["<b>init 役割</b><br/>ゾンビ刈取り<br/>signal 転送 · 終了コード伝播"]
end

subgraph SPEC["◤ 実行仕様の組立 ◢"]
    X1["<b>OCI runtime spec 相当</b><br/>Pod spec → 実行パラメータ<br/>securityContext 反映"]
    X2["<b>Sandbox / Container の分離</b><br/>Sandbox が ns を保持<br/>コンテナは join する"]
end

subgraph MON["◤ 監視と回収 ◢"]
    M1["<b>pidfd 監視</b><br/>終了コード · シグナル要因<br/>PID再利用を排除"]
    M2["<b>OOM 検出</b><br/>memory.events 購読"]
    M3["<b>ログ収集</b><br/>stdout/stderr → ファイル<br/>ローテート · follow 配信"]
    M4["<b>Stats</b><br/>cgroup + /proc から集計"]
    M5["<b>後片付け</b><br/>cgroup 削除 · mount 解除<br/>upperdir 破棄 · pty 解放"]
end

I1 --> I2 --> I3 --> I4 --> I5 --> I6 --> I7
I8 -.-> I4
I6 --> F1
I7 --> X1
SPEC --> X1 --> X2
X2 --> N1
N1 --> N2
N1 --> N3 --> F2
N1 --> N4
N1 --> N5
N1 --> N6
N1 --> N7
N1 --> N8
N9 -.-> N4
F1 --> F2 --> F3 --> F4 --> F5
F6 -.-> F3
F7 -.-> F4
X2 --> G1 --> G2
G1 --> G3
G1 --> G4
G1 --> G5
G1 --> G6
G7 -.-> G1
N7 --> P2
P1 --> P2 --> P3
F3 --> P3
G1 --> P3
P3 --> S1 --> S2
P3 --> S3 --> S4
S5 -.-> P3
S6 -.-> S3
S2 --> P4 --> P5 --> P6 --> P7
S4 --> P6
P7 --> M1 --> M5
G3 -.-> M2 --> M1
P4 --> M3
G6 --> M4
M4 -->|"Stats 応答"| IF
M1 -->|"終了通知"| IF
M3 -->|"logs 応答"| IF

classDef if fill:#16202a,stroke:#4b9fd6,color:#e6ecf5
classDef oc fill:#12202e,stroke:#4b9fd6,color:#e6ecf5
classDef fs fill:#1d2431,stroke:#7f8da5,color:#e6ecf5
classDef ns fill:#1b1630,stroke:#8b6ef0,color:#e6ecf5
classDef cg fill:#241320,stroke:#e0294b,color:#e6ecf5
classDef se fill:#2a1a24,stroke:#ff5c78,color:#e6ecf5
classDef pr fill:#251a12,stroke:#e0a029,color:#e6ecf5
classDef mo fill:#101c1a,stroke:#3fae8f,color:#e6ecf5

class IF,NATIVE,MICRO,RESTRICT,LIFE,L1,L2,L3,L4,L5,X1,X2,SPEC if
class V1,V2,V3,V4,V5 se
class I1,I2,I3,I4,I5,I6,I7,I8 oc
class F1,F2,F3,F4,F5,F6,F7 fs
class N1,N2,N3,N4,N5,N6,N7,N8,N9 ns
class G1,G2,G3,G4,G5,G6,G7 cg
class S1,S2,S3,S4,S5,S6 se
class P1,P2,P3,P4,P5,P6,P7 pr
class M1,M2,M3,M4,M5 mo
```

## Related

- [runtime](../node/runtime.md)
- [formal methods](../verification/formal-methods.md)
- [構成図インデックス](README.md)
