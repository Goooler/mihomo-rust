#!/usr/bin/env bash
# End-to-end TUN mode integration test using QEMU.
#
# Boots a minimal Linux VM with mihomo, creates a TUN device,
# and verifies device creation, IP/MTU assignment, and netstack
# packet processing.
#
# Requirements: qemu-system-x86_64, busybox (static), Linux kernel
#
# Usage: bash tests/test_tun_qemu.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR="$(mktemp -d)"
QEMU_TIMEOUT=120

VMLINUZ_COPY=""
cleanup() {
    echo "Cleaning up $WORK_DIR..."
    rm -rf "$WORK_DIR"
    [ -n "$VMLINUZ_COPY" ] && rm -f "$VMLINUZ_COPY"
}
trap cleanup EXIT

# --- Dependency checks (graceful skip) ---
check_command() {
    if ! command -v "$1" &>/dev/null; then
        echo "SKIP: $1 not found in PATH"
        exit 0
    fi
}

check_command qemu-system-x86_64
check_command cpio
check_command busybox

# Find Linux kernel image
VMLINUZ=""
for candidate in /boot/vmlinuz-*; do
    if [ -f "$candidate" ]; then
        VMLINUZ="$candidate"
        break
    fi
done

if [ -z "$VMLINUZ" ]; then
    echo "SKIP: No Linux kernel found in /boot/vmlinuz-*"
    exit 0
fi
echo "Using kernel: $VMLINUZ"

# Kernel images are often root-only (0600). Copy to a readable temp location.
if [ ! -r "$VMLINUZ" ]; then
    VMLINUZ_COPY="$(mktemp)"
    sudo cp "$VMLINUZ" "$VMLINUZ_COPY"
    sudo chmod 644 "$VMLINUZ_COPY"
    VMLINUZ="$VMLINUZ_COPY"
    echo "Copied kernel to readable temp: $VMLINUZ"
fi

# --- Build mihomo ---
echo ""
echo "=== Building mihomo ==="
cd "$ROOT_DIR"
cargo build -p mihomo-app 2>&1

# Find the built binary (check debug first, then release)
MIHOMO_BIN=""
if [ -f "$ROOT_DIR/target/debug/mihomo" ]; then
    MIHOMO_BIN="$ROOT_DIR/target/debug/mihomo"
elif [ -f "$ROOT_DIR/target/release/mihomo" ]; then
    MIHOMO_BIN="$ROOT_DIR/target/release/mihomo"
else
    echo "FAIL: mihomo binary not found in target/debug or target/release"
    exit 1
fi
echo "Using mihomo binary: $MIHOMO_BIN"

# Verify it's a Linux x86_64 binary
FILE_TYPE=$(file "$MIHOMO_BIN")
if ! echo "$FILE_TYPE" | grep -q "ELF.*x86-64"; then
    echo "SKIP: mihomo binary is not Linux x86_64 (got: $FILE_TYPE)"
    exit 0
fi

# --- Build initramfs ---
echo ""
echo "=== Building initramfs ==="
INITRAMFS_DIR="$WORK_DIR/initramfs"
mkdir -p "$INITRAMFS_DIR"/{bin,dev,dev/net,proc,sys,lib/modules,etc}

# Install busybox and create symlinks
BUSYBOX_BIN=$(command -v busybox)
cp "$BUSYBOX_BIN" "$INITRAMFS_DIR/bin/busybox"
chmod +x "$INITRAMFS_DIR/bin/busybox"

# Create busybox symlinks for essential tools
for cmd in sh ash ip nc grep cat echo sleep seq mount mkdir mknod modprobe \
           kill sync poweroff reboot ln ls ps head tail wc sort tr timeout; do
    ln -sf busybox "$INITRAMFS_DIR/bin/$cmd"
done

# Copy mihomo binary and config
cp "$MIHOMO_BIN" "$INITRAMFS_DIR/mihomo"
chmod +x "$INITRAMFS_DIR/mihomo"

# Copy dynamic libraries required by mihomo
mkdir -p "$INITRAMFS_DIR/lib64" "$INITRAMFS_DIR/lib/x86_64-linux-gnu"
if ldd "$MIHOMO_BIN" >/dev/null 2>&1; then
    ldd "$MIHOMO_BIN" | grep -oP '/\S+' | while read -r lib; do
        if [ -f "$lib" ]; then
            cp "$lib" "$INITRAMFS_DIR/lib/x86_64-linux-gnu/" 2>/dev/null || true
        fi
    done
    # Copy dynamic linker
    if [ -f /lib64/ld-linux-x86-64.so.2 ]; then
        cp /lib64/ld-linux-x86-64.so.2 "$INITRAMFS_DIR/lib64/"
    fi
    echo "Copied dynamic libraries for mihomo"
fi

cp "$SCRIPT_DIR/tun-qemu/mihomo-tun.yaml" "$INITRAMFS_DIR/mihomo-tun.yaml"

# Copy guest-init.sh as /init
cp "$SCRIPT_DIR/tun-qemu/guest-init.sh" "$INITRAMFS_DIR/init"
chmod +x "$INITRAMFS_DIR/init"

# Copy TUN kernel module if available
KVER=$(uname -r)
TUN_MOD_PATHS=(
    "/lib/modules/$KVER/kernel/drivers/net/tun.ko"
    "/lib/modules/$KVER/kernel/drivers/net/tun.ko.xz"
    "/lib/modules/$KVER/kernel/drivers/net/tun.ko.zst"
)
for mod_path in "${TUN_MOD_PATHS[@]}"; do
    if [ -f "$mod_path" ]; then
        mkdir -p "$INITRAMFS_DIR/lib/modules/$KVER/kernel/drivers/net"
        cp "$mod_path" "$INITRAMFS_DIR/lib/modules/$KVER/kernel/drivers/net/"
        echo "Copied TUN module: $mod_path"
        break
    fi
done

# Create the cpio archive
echo "Creating initramfs archive..."
cd "$INITRAMFS_DIR"
find . | cpio -o -H newc --quiet 2>/dev/null | gzip > "$WORK_DIR/initramfs.cpio.gz"
cd "$ROOT_DIR"

INITRAMFS_SIZE=$(du -h "$WORK_DIR/initramfs.cpio.gz" | cut -f1)
echo "Initramfs size: $INITRAMFS_SIZE"

# --- Boot QEMU ---
echo ""
echo "=== Booting QEMU VM ==="

# Auto-detect KVM support
QEMU_ACCEL=""
if [ -w /dev/kvm ] 2>/dev/null; then
    QEMU_ACCEL="-enable-kvm"
    echo "KVM acceleration enabled"
else
    echo "KVM not available, using TCG (slower)"
fi

SERIAL_LOG="$WORK_DIR/serial.log"

timeout "$QEMU_TIMEOUT" qemu-system-x86_64 \
    -kernel "$VMLINUZ" \
    -initrd "$WORK_DIR/initramfs.cpio.gz" \
    -append "console=ttyS0 panic=-1" \
    -nographic \
    -no-reboot \
    -m 512M \
    -smp 2 \
    $QEMU_ACCEL \
    2>&1 | tee "$SERIAL_LOG" || true

echo ""
echo "=== Parsing test results ==="

# Parse results
PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

while IFS= read -r line; do
    test_name="${line#TEST_PASS:}"
    echo "  PASS: $test_name"
    PASS_COUNT=$((PASS_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
done < <(grep "^TEST_PASS:" "$SERIAL_LOG" 2>/dev/null || true)

while IFS= read -r line; do
    test_name="${line#TEST_FAIL:}"
    echo "  FAIL: $test_name"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
done < <(grep "^TEST_FAIL:" "$SERIAL_LOG" 2>/dev/null || true)

echo ""
echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed, $TOTAL_COUNT total"

# Check for GUEST_DONE marker
if ! grep -q "GUEST_DONE" "$SERIAL_LOG" 2>/dev/null; then
    echo ""
    echo "WARNING: GUEST_DONE marker not found — VM may have crashed or timed out"
    echo ""
    echo "=== Last 30 lines of serial output ==="
    tail -30 "$SERIAL_LOG" 2>/dev/null || true
fi

# Determine exit code
if [ "$TOTAL_COUNT" -eq 0 ]; then
    echo ""
    echo "=== FAIL: No tests ran ==="
    exit 1
elif [ "$FAIL_COUNT" -gt 0 ]; then
    echo ""
    echo "=== FAIL: $FAIL_COUNT test(s) failed ==="
    exit 1
else
    echo ""
    echo "=== All TUN QEMU integration tests passed ==="
    exit 0
fi
