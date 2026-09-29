#!/bin/sh
# Builds the pinned Rubernetes guest kernel: Linux 6.1.128 with the
# Firecracker v1.16.1 microVM CI configuration plus the options the Ruby
# guest supervisor needs to run the Native L3 isolation profile inside the
# guest (Landlock, cgroup v2 controllers, seccomp, overlayfs, vsock).
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${RUBERNETES_KERNEL_WORKDIR:-$ROOT/build/microvm/kernel}"
VERSION="6.1.128"
SOURCE_SHA256="874d67d3181570e69ac6b33853f0448f05fc90d4cf3e4baaadc4a9cede7c50f3"
CONFIG_SHA256="adbc70ab5e89213ba00594b12d25e09bdf8bb1ed3c252d7449326bb14c22963b"
KERNEL_CC="${RUBERNETES_KERNEL_CC:-/usr/bin/gcc}"
"$KERNEL_CC" --version | head -1
cd "$WORK"
echo "$SOURCE_SHA256  linux-$VERSION.tar.xz" | sha256sum -c -
echo "$CONFIG_SHA256  microvm-kernel-ci-x86_64-6.1.config" | sha256sum -c -
rm -rf "linux-$VERSION"
tar xf "linux-$VERSION.tar.xz"
cd "linux-$VERSION"
cp ../microvm-kernel-ci-x86_64-6.1.config .config
scripts/config --enable CONFIG_SECURITY_LANDLOCK \
  --set-str CONFIG_LSM "landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf" \
  --enable CONFIG_SECCOMP --enable CONFIG_SECCOMP_FILTER \
  --enable CONFIG_OVERLAY_FS --enable CONFIG_CGROUPS --enable CONFIG_CGROUP_PIDS --enable CONFIG_CGROUP_CPUACCT \
  --enable CONFIG_MEMCG --enable CONFIG_CPUSETS --enable CONFIG_BLK_CGROUP --enable CONFIG_CGROUP_SCHED \
  --enable CONFIG_USER_NS --enable CONFIG_PID_NS --enable CONFIG_NET_NS --enable CONFIG_UTS_NS --enable CONFIG_IPC_NS --enable CONFIG_CGROUP_NS \
  --enable CONFIG_VSOCKETS --enable CONFIG_VIRTIO_VSOCKETS --enable CONFIG_TUN --enable CONFIG_IKCONFIG --enable CONFIG_IKCONFIG_PROC \
  --enable CONFIG_DM_VERITY --enable CONFIG_BLK_DEV_DM --enable CONFIG_DEVTMPFS --enable CONFIG_DEVTMPFS_MOUNT \
  --enable CONFIG_MAGIC_SYSRQ --enable CONFIG_SQUASHFS --enable CONFIG_EXT4_FS --enable CONFIG_TMPFS --enable CONFIG_BPF_SYSCALL \
  --enable CONFIG_PSI --disable CONFIG_PSI_DEFAULT_DISABLED --enable CONFIG_CGROUP_FREEZER --enable CONFIG_MEMCG_KMEM
make CC="$KERNEL_CC" HOSTCC="$KERNEL_CC" olddefconfig
make CC="$KERNEL_CC" HOSTCC="$KERNEL_CC" -j"$(nproc)" vmlinux
cp vmlinux ../vmlinux-rubernetes-$VERSION
cp .config ../vmlinux-rubernetes-$VERSION.config
sha256sum ../vmlinux-rubernetes-$VERSION
