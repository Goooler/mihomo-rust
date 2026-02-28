#!/bin/busybox sh
# guest-init.sh — Runs as PID 1 inside the QEMU VM.
# Boots the minimal environment, starts mihomo with TUN config,
# runs test assertions, and prints results to serial console.

# Do NOT use set -e — as PID 1, any exit kills the VM with a kernel panic.

# --- Early boot: mount virtual filesystems ---
mount -t proc proc /proc || true
mount -t sysfs sysfs /sys || true
mount -t devtmpfs devtmpfs /dev || true
mkdir -p /dev/net

# Install busybox symlinks
/bin/busybox --install -s /bin

# Load TUN kernel module and create device node
modprobe tun 2>/dev/null || true
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
fi

# Set up loopback interface
ip link set lo up
ip addr add 127.0.0.1/8 dev lo

echo "=== Guest VM booted ==="

# --- Start mihomo ---
/mihomo -f /mihomo-tun.yaml > /mihomo.log 2>&1 &
MIHOMO_PID=$!
echo "mihomo started (PID $MIHOMO_PID)"

# --- Wait for TUN listener to be ready (up to 10s) ---
READY=0
for i in $(seq 1 20); do
    if grep -q "TUN listener running" /mihomo.log 2>/dev/null; then
        READY=1
        echo "TUN listener ready after $((i * 500))ms"
        break
    fi
    sleep 0.5
done

echo ""
echo "=== Running test assertions ==="

# Helper function
pass() { echo "TEST_PASS:$1"; }
fail() { echo "TEST_FAIL:$1"; }

# Test 1: tun_ready — "TUN listener running" appears in log
if [ "$READY" -eq 1 ]; then
    pass "tun_ready"
else
    fail "tun_ready"
fi

# Test 2: device_exists — ip link show tun-test succeeds
if ip link show tun-test >/dev/null 2>&1; then
    pass "device_exists"
else
    fail "device_exists"
fi

# Test 3: device_ip — ip addr show tun-test contains 198.18.0.1
if ip addr show tun-test 2>/dev/null | grep -q "198.18.0.1"; then
    pass "device_ip"
else
    fail "device_ip"
fi

# Test 4: device_mtu — ip link show tun-test contains "mtu 1400"
if ip link show tun-test 2>/dev/null | grep -q "mtu 1400"; then
    pass "device_mtu"
else
    fail "device_mtu"
fi

# Test 5: mihomo_alive — mihomo process is still running
if kill -0 "$MIHOMO_PID" 2>/dev/null; then
    pass "mihomo_alive"
else
    fail "mihomo_alive"
fi

# Test 6: log_tun_created — Log contains device creation message
if grep -q "TUN device created: addr=198.18.0.1/16, mtu=1400" /mihomo.log 2>/dev/null; then
    pass "log_tun_created"
else
    fail "log_tun_created"
fi

# Test 7: netstack_tcp — TCP packet routed through TUN reaches netstack
# Add a route so traffic to 10.99.0.0/24 goes through the TUN device
ip route add 10.99.0.0/24 dev tun-test 2>/dev/null || true

# Send a TCP connection attempt to 10.99.0.1:18400 via nc
# The connection will fail (nothing listening there) but netstack should
# process the packet and mihomo will log the destination address.
# Wrap in timeout because busybox nc -w may block on connect().
timeout 5 sh -c 'echo "test" | nc -w 2 10.99.0.1 18400' 2>/dev/null || true

# Give mihomo a moment to process and log
sleep 2

if grep -q "10.99.0.1:18400" /mihomo.log 2>/dev/null; then
    pass "netstack_tcp"
else
    fail "netstack_tcp"
fi

echo ""
echo "GUEST_DONE"

# Dump full log for debugging
echo ""
echo "=== Full mihomo log ==="
cat /mihomo.log 2>/dev/null || echo "(no log file)"
echo "=== End of log ==="

# Shutdown
sync
poweroff -f
