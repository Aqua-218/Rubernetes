# ネイティブ拡張

[English](README.md) | 日本語

`rubernetes_linux/`には、RubyのFFIでは安全に書けないABI用のshimだけを置きます。型付きのシステムコールと、構造体のレイアウトを調べるプローブは公開してかまいません。ポリシー、状態機械、再試行、認可、スケジューリング、資源のライフサイクルについての判断は、ここに置いてはいけません。

M0で使うネイティブの操作は`clone3_exec`の1つだけです。Rubyが、フラグ、argv、procのマウント先、出力用のディスクリプタを渡します。shimが行うのは、cloneのあとの処理のうち、forkを意識していないRuby VMを通って安全に戻れない部分だけです。具体的には、privateなマウント、procのマウント、ディスクリプタの設定、`execve`です。

子プロセスで失敗が起きた場合は、`{stage, errno}`を親に送り返します。親はこれを、失敗した段階と`errno`を持つRubyの例外にします。

## 関連

- [ランタイム](../spec/node/runtime.md)
- [コーディング規約](../spec/delivery/coding-standards.md)
- [マイルストーンM0](../spec/delivery/milestones.md#milestone-m0)
