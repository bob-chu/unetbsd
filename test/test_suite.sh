#!/bin/bash
set -e

# Configs
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SHIM_LIB="/app/build/libnetbsdshim.so"
NS_S="ns_server"
NS_C="ns_client"
IF_S="veth0" # Server Interface
IF_C="veth1" # Client Interface
IP_S="10.0.0.1"
IP_C="10.0.0.2"
MAC_S="42:94:f1:f1:12:fd"
MAC_C="8e:db:f8:b4:aa:ca"

setup_env() {
    echo "[Env] Creating namespaces..."
    ip netns delete $NS_S 2>/dev/null || true
    ip netns delete $NS_C 2>/dev/null || true
    
    ip netns add $NS_S 
    ip netns add $NS_C 
    
    # Ensure veth pair exists (delete and recreate to be safe)
    ip link delete $IF_C 2>/dev/null || true
    ip link delete $IF_S 2>/dev/null || true
    
    echo "      Creating veth pair $IF_C <-> $IF_S..."
    ip link add $IF_C type veth peer name $IF_S

    # Set MACs
    ip link set $IF_S address $MAC_S
    ip link set $IF_C address $MAC_C

    # Move to namespaces
    ip link set $IF_S netns $NS_S
    ip link set $IF_C netns $NS_C

    # Bring UP
    ip netns exec $NS_S ip link set $IF_S up
    ip netns exec $NS_C ip link set $IF_C up
    # Loopback
    ip netns exec $NS_S ip link set lo up
    ip netns exec $NS_C ip link set lo up
    
    # Disable checksum offloading to ensure valid checksums for shim
    ip netns exec $NS_S ethtool -K $IF_S rx off tx off sg off tso off gso off
    ip netns exec $NS_C ethtool -K $IF_C rx off tx off sg off tso off gso off

    
    # Disable rp_filter (ALL of them)
    ip netns exec $NS_S sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    ip netns exec $NS_S sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
    ip netns exec $NS_S sysctl -w net.ipv4.conf.$IF_S.rp_filter=0 >/dev/null
    
    ip netns exec $NS_C sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    ip netns exec $NS_C sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
    ip netns exec $NS_C sysctl -w net.ipv4.conf.$IF_C.rp_filter=0 >/dev/null
    
    # Drop kernel-generated RST packets for userspace TCP stack
    ip netns exec $NS_S iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true
    ip netns exec $NS_C iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true
}

cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    pkill iperf3 || true
    ip netns delete $NS_S 2>/dev/null || true
    ip netns delete $NS_C 2>/dev/null || true
}

gen_config() {
    local IP=$1
    local IF=$2
    local MAC=$3
    local FILE=$4
    cat <<EOF > $FILE
{
    "interfaces": [
        {
            "param": "$IF",
            "ip": "$IP",
            "mac": "$MAC",
            "masklen": "24",
            "mtu": "1500"
        }
    ],
    "gateway": "0.0.0.0",
    "debug": "0"
}
EOF
}

gen_dpdk_config() {
    local IP=$1
    local IF=$2
    local MAC=$3
    local FILE=$4
    local CORES=$5
    local PREFIX=$6
    cat <<EOF > $FILE
{
    "backend": "dpdk",
    "dpdk_args": "--vdev=net_af_packet0,iface=$IF --no-huge -l $CORES --in-memory --proc-type=primary --file-prefix=$PREFIX",
    "interfaces": [
        {
            "param": "net_af_packet0",
            "ip": "$IP",
            "mac": "$MAC",
            "masklen": "24",
            "mtu": "1500"
        }
    ],
    "gateway": "0.0.0.0",
    "debug": "0"
}
EOF
}

gen_dpdk_memif_config() {
    local IP=$1
    local MAC=$2
    local FILE=$3
    local CORES=$4
    local PREFIX=$5
    local ROLE=$6
    cat <<EOF > $FILE
{
    "backend": "dpdk",
    "dpdk_args": "--vdev=net_memif,role=$ROLE,id=0,bsize=9216 --log-level=pmd.net.memif:debug -l $CORES --proc-type=primary --file-prefix=$PREFIX",
    "interfaces": [
        {
            "param": "net_memif",
            "ip": "$IP",
            "mac": "$MAC",
            "masklen": "24",
            "mtu": "1500"
        }
    ],
    "gateway": "0.0.0.0",
    "debug": "0"
}
EOF
}

test_std_std() {
    echo ""
    echo "=== Test 1: Std Client -> Std Server (Baseline) ==="
    # Kernel networking setup
    ip netns exec $NS_S ip addr add $IP_S/24 dev $IF_S
    ip netns exec $NS_C ip addr add $IP_C/24 dev $IF_C
    
    # Check connectivity
    if ! ip netns exec $NS_C ping -c 1 $IP_S >/dev/null; then
        echo "❌ Ping failed!"
        return 1
    fi
    
    # Server
    ip netns exec $NS_S iperf3 -s -4 > s1.log 2>&1 &
    SPID=$!
    sleep 1
    
    # Client
    if ip netns exec $NS_C timeout -s KILL 20s iperf3 -c $IP_S -4 -t 5; then
        echo "✅ Test 1 Passed"
    else
        echo "❌ Test 1 Failed"
    fi
    
    kill $SPID || true
    # Cleanup IP
    ip netns exec $NS_S ip addr flush dev $IF_S
    ip netns exec $NS_C ip addr flush dev $IF_C
}

test_std_shim() {
    echo ""
    echo "=== Test 2: Std Client -> Shim Server ==="
    # Client (Std) gets Kernel IP
    ip netns exec $NS_C ip addr add $IP_C/24 dev $IF_C
    
    # Server (Shim) - No Kernel IP needed on IF_S
    gen_config $IP_S $IF_S $MAC_S "shim_server.json"
    
    echo "      Starting Shim Server..."
    ip netns exec $NS_S bash -c "NETBSD_HIJACK_CONFIG_FILE=$(pwd)/shim_server.json LD_PRELOAD=$SHIM_LIB iperf3 -s -4" > s2.log 2>&1 &
    SPID=$!
    sleep 2
    
    echo "      Verifying ARP..."
    if ! ip netns exec $NS_C ping -c 1 $IP_S >/dev/null 2>&1; then
        echo "      ARP probe via arping..."
        ip netns exec $NS_C arping -c 1 $IP_S || true
        sleep 1
    fi
    
    echo "      Running iperf3 client..."
    if ip netns exec $NS_C timeout -s KILL 20s iperf3 -c $IP_S -4 -t 5; then
        echo "✅ Test 2 Passed"
    else
        echo "❌ Test 2 Failed. Server Log:"
        cat s2.log
    fi
    
    kill $SPID || true
    ip netns exec $NS_C ip addr flush dev $IF_C
}

test_shim_std() {
    echo ""
    echo "=== Test 3: Shim Client -> Std Server ==="
    # Server (Std) gets Kernel IP
    ip netns exec $NS_S ip addr add $IP_S/24 dev $IF_S
    
    # Client (Shim)
    gen_config $IP_C $IF_C $MAC_C "shim_client.json"
    
    echo "      Starting Std Server..."
    ip netns exec $NS_S iperf3 -s -4 > s3.log 2>&1 &
    SPID=$!
    sleep 1
    
    echo "      Running Shim Client..."
    if ip netns exec $NS_C timeout -s KILL 20s bash -c "NETBSD_HIJACK_CONFIG_FILE=$(pwd)/shim_client.json LD_PRELOAD=$SHIM_LIB iperf3 -c $IP_S -4 -t 5"; then
        echo "✅ Test 3 Passed"
    else
        echo "❌ Test 3 Failed"
    fi
    
    kill $SPID || true
    ip netns exec $NS_S ip addr flush dev $IF_S
}

test_shim_shim() {
    echo ""
    echo "=== Test 4: Shim Client -> Shim Server ==="
    
    gen_config $IP_S $IF_S $MAC_S "shim_server.json"
    gen_config $IP_C $IF_C $MAC_C "shim_client.json"
    
    echo "      Starting Shim Server..."
    ip netns exec $NS_S bash -c "NETBSD_HIJACK_CONFIG_FILE=$(pwd)/shim_server.json LD_PRELOAD=$SHIM_LIB iperf3 -s -4" > s4.log 2>&1 &
    SPID=$!
    sleep 2
    
    echo "      Running Shim Client..."
    if ip netns exec $NS_C timeout -s KILL 20s bash -c "NETBSD_HIJACK_CONFIG_FILE=$(pwd)/shim_client.json LD_PRELOAD=$SHIM_LIB iperf3 -c $IP_S -4 -t 5"; then
        echo "✅ Test 4 Passed"
    else
        echo "❌ Test 4 Failed. Server Log:"
        cat s4.log
    fi
    
    kill $SPID || true
}

test_dpdk_std() {
    echo ""
    echo "=== Test 5: DPDK Client -> Std Server ==="
    # Server (Std) gets Kernel IP
    ip netns exec $NS_S ip addr add $IP_S/24 dev $IF_S
    
    # Client uses DPDK with AF_PACKET - use different IP to avoid conflict
    gen_dpdk_config "10.0.0.5" $IF_C $MAC_C "dpdk_client.json" "0" "dpdk_client"
    
    echo "      Starting Std Server..."
    ip netns exec $NS_S iperf3 -s -4 > s5.log 2>&1 &
    SPID=$!
    sleep 1
    
    echo "      Running DPDK Client..."
    if ip netns exec $NS_C timeout -s KILL 30s bash -c "NETBSD_HIJACK_CONFIG_FILE=$(pwd)/dpdk_client.json LD_PRELOAD=$SHIM_LIB iperf3 -c $IP_S -4 -t 5" 2>&1; then
        echo "✅ Test 5 Passed"
    else
        echo "❌ Test 5 Failed"
    fi
    
    kill $SPID || true
    ip netns exec $NS_S ip addr flush dev $IF_S
}

test_std_dpdk() {
    echo ""
    echo "=== Test 6: Std Client -> DPDK Server ==="
    # Client (Std) gets Kernel IP
    ip netns exec $NS_C ip addr add $IP_C/24 dev $IF_C
    
    # Server uses DPDK with AF_PACKET
    gen_dpdk_config $IP_S $IF_S $MAC_S "dpdk_server.json" "1" "dpdk_server"
    
    echo "      Starting DPDK Server..."
    ip netns exec $NS_S bash -c "NETBSD_HIJACK_CONFIG_FILE=$(pwd)/dpdk_server.json LD_PRELOAD=$SHIM_LIB iperf3 -s -4" > s6.log 2>&1 &
    SPID=$!
    sleep 3
    
    echo "      Verifying ARP..."
    ip netns exec $NS_C arping -c 1 $IP_S || true
    sleep 1
    
    echo "      Running Std Client..."
    if ip netns exec $NS_C timeout -s KILL 30s iperf3 -c $IP_S -4 -t 5; then
        echo "✅ Test 6 Passed"
    else
        echo "❌ Test 6 Failed. Server Log:"
        cat s6.log
    fi
    
    kill $SPID || true
    ip netns exec $NS_C ip addr flush dev $IF_C
}

test_dpdk_dpdk() {
    echo ""
    echo "=== Test 7: DPDK Client -> DPDK Server ==="
    
    gen_dpdk_config $IP_S $IF_S $MAC_S "dpdk_server.json" "0" "dpdk_server"
    gen_dpdk_config "10.0.0.5" $IF_C $MAC_C "dpdk_client.json" "1" "dpdk_client"
    
    echo "      Starting DPDK Server..."
    ip netns exec $NS_S bash -c "NETBSD_HIJACK_CONFIG_FILE=$(pwd)/dpdk_server.json LD_PRELOAD=$SHIM_LIB iperf3 -s -4" > s7.log 2>&1 &
    SPID=$!
    sleep 3
    
    echo "      Running DPDK Client..."
    if ip netns exec $NS_C timeout -s KILL 30s bash -c "NETBSD_HIJACK_CONFIG_FILE=$(pwd)/dpdk_client.json LD_PRELOAD=$SHIM_LIB iperf3 -c $IP_S -4 -t 5" 2>&1; then
        echo "✅ Test 7 Passed"
    else
        echo "❌ Test 7 Failed. Server Log:"
        cat s7.log
    fi
    
    kill $SPID || true
}

test_dpdk_memif() {
    echo ""
    echo "=== Test 8: DPDK Client -> DPDK Server (Memif) ==="
    
    # Memif requires hugepages or --no-huge, cleanup socket first
    rm -f /run/memif.sock
    
    gen_dpdk_memif_config $IP_S $MAC_S "shim_server_memif.json" "0" "memif_server" "server"
    gen_dpdk_memif_config "10.0.0.5" $MAC_C "shim_client_memif.json" "1" "memif_client" "client"
    
    echo "      Starting Memif Server..."
    NETBSD_HIJACK_CONFIG_FILE=$(pwd)/shim_server_memif.json LD_PRELOAD=$SHIM_LIB iperf3 -s -4 > s8.log 2>&1 &
    SPID=$!
    sleep 3
    
    echo "      Running Memif Client..."
    if timeout -s KILL 30s bash -c "NETBSD_HIJACK_CONFIG_FILE=$(pwd)/shim_client_memif.json LD_PRELOAD=$SHIM_LIB iperf3 -c $IP_S -4 -t 5" 2>&1; then
        echo "✅ Test 8 Passed"
    else
        echo "❌ Test 8 Failed. Server Log:"
        cat s8.log
    fi

    kill $SPID || true
    rm -f /run/memif.sock
}

test_rtc() {
    echo ""
    echo "=== Test 9: RTC Benchmark (Dual-Socket) ==="
    
    # Ensure binaries exist
    if [ ! -f "$PROJECT_ROOT/build/test_rtc_server" ] || [ ! -f "$PROJECT_ROOT/build/test_rtc_client" ]; then
        echo "❌ RTC binaries not found. Please build first."
        return 1
    fi

    echo "      Starting RTC Server..."
    rm -f server_rtc.log
    ip netns exec $NS_S bash -c "NETBSD_RTC_MODE=1 NETBSD_BACKEND=af_packet $PROJECT_ROOT/build/test_rtc_server $IF_S $IP_S" > server_rtc.log 2>&1 &
    SPID=$!
    sleep 2
    
    echo "      Starting RTC Client..."
    if ip netns exec $NS_C timeout 10s bash -c "NETBSD_RTC_MODE=1 NETBSD_BACKEND=af_packet $PROJECT_ROOT/build/test_rtc_client $IF_C $IP_C $IP_S" > client_rtc.log 2>&1; then
        if grep -q "Gbps" client_rtc.log; then
             THROUGHPUT=$(grep "Gbps" client_rtc.log | tail -n 1)
             echo "✅ Test 9 Passed. Performance: $THROUGHPUT"
        else
             echo "❌ Test 9 Failed (No throughput found). Server Log:"
             cat server_rtc.log
        fi
    else
        echo "❌ Test 9 Failed (Client crashed/timeout). Server Log:"
        cat server_rtc.log
    fi
    
    kill $SPID || true
}

test_rtc_dpdk_af_packet() {
    echo ""
    echo "=== Test 10: RTC Benchmark (DPDK AF_PACKET) ==="
    
    # Ensure binaries exist
    if [ ! -f "$PROJECT_ROOT/build/test_rtc_server" ] || [ ! -f "$PROJECT_ROOT/build/test_rtc_client" ]; then
        echo "❌ RTC binaries not found. Please build first."
        return 1
    fi
    
    # Use config files
    gen_dpdk_config $IP_S $IF_S $MAC_S "rtc_server_af.json" "0" "pbs"
    gen_dpdk_config $IP_C $IF_C $MAC_C "rtc_client_af.json" "1" "pbc"

    echo "      Starting RTC Server..."
    rm -f server_rtc_dpdk.log
    ip netns exec $NS_S bash -c "NETBSD_RTC_MODE=1 NETBSD_HIJACK_CONFIG_FILE=$(pwd)/rtc_server_af.json $PROJECT_ROOT/build/test_rtc_server" > server_rtc_dpdk.log 2>&1 &
    SPID=$!
    sleep 3
    
    echo "      Starting RTC Client..."
    # TARGET_IP env var needed for client to know where to connect
    if ip netns exec $NS_C timeout 10s bash -c "NETBSD_RTC_MODE=1 NETBSD_HIJACK_CONFIG_FILE=$(pwd)/rtc_client_af.json TARGET_IP=$IP_S $PROJECT_ROOT/build/test_rtc_client" > client_rtc_dpdk.log 2>&1; then
        if grep -q "Gbps" client_rtc_dpdk.log; then
             THROUGHPUT=$(grep "Gbps" client_rtc_dpdk.log | tail -n 1)
             echo "✅ Test 10 Passed. Performance: $THROUGHPUT"
        else
             echo "❌ Test 10 Failed (No throughput found). Server Log:"
             cat server_rtc_dpdk.log
        fi
    else
        echo "❌ Test 10 Failed (Client crashed/timeout). Server Log:"
        cat server_rtc_dpdk.log
    fi
    
    kill $SPID || true
}

test_rtc_dpdk_memif() {
    echo ""
    echo "=== Test 11: RTC Benchmark (DPDK Memif) ==="
    
    rm -f /run/memif.sock
    
    gen_dpdk_memif_config $IP_S $MAC_S "rtc_server_memif.json" "0" "pms" "server"
    gen_dpdk_memif_config $IP_C $MAC_C "rtc_client_memif.json" "1" "pmc" "client"

    echo "      Starting RTC Server (Memif)..."
    rm -f server_rtc_memif.log
    # Note: Memif requires shared /run, so we run WITHOUT ip netns exec (like Test 8)
    NETBSD_RTC_MODE=1 NETBSD_HIJACK_CONFIG_FILE=$(pwd)/rtc_server_memif.json $PROJECT_ROOT/build/test_rtc_server > server_rtc_memif.log 2>&1 &
    SPID=$!
    sleep 3
    
    echo "      Starting RTC Client (Memif)..."
    if timeout 10s bash -c "NETBSD_RTC_MODE=1 NETBSD_HIJACK_CONFIG_FILE=$(pwd)/rtc_client_memif.json TARGET_IP=$IP_S $PROJECT_ROOT/build/test_rtc_client" > client_rtc_memif.log 2>&1; then
        if grep -q "Gbps" client_rtc_memif.log; then
             THROUGHPUT=$(grep "Gbps" client_rtc_memif.log | tail -n 1)
             echo "✅ Test 11 Passed. Performance: $THROUGHPUT"
        else
             echo "❌ Test 11 Failed (No throughput found). Server Log:"
             cat server_rtc_memif.log
        fi
    else
        echo "❌ Test 11 Failed (Client crashed/timeout). Server Log:"
        cat server_rtc_memif.log
    fi
    
    kill $SPID || true
    rm -f /run/memif.sock
}

# Main execution
echo "🚀 Starting Comprehensive Test Suite..."

TEST_TO_RUN=$1
if [ "$TEST_TO_RUN" == "--test" ]; then
    TEST_TO_RUN=$2
fi

setup_env

run_test() {
    local num=$1
    local name=$2
    if [ -z "$TEST_TO_RUN" ] || [ "$TEST_TO_RUN" == "$num" ]; then
        $name
    fi
}

run_test 1 test_std_std
run_test 2 test_std_shim
run_test 3 test_shim_std
run_test 4 test_shim_shim
run_test 5 test_dpdk_std
run_test 6 test_std_dpdk
run_test 7 test_dpdk_dpdk
run_test 8 test_dpdk_memif
run_test 9 test_rtc
run_test 10 test_rtc_dpdk_af_packet
run_test 11 test_rtc_dpdk_memif

cleanup
echo "🎉 All requested tests completed."
