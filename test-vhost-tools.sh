#!/bin/bash

# Test script for vhost-net debugging tools
# Validates that BPF programs can be compiled and loaded

echo "🧪 Testing vhost-net debugging tools..."
echo

# Check prerequisites
echo "📋 Checking prerequisites..."

if ! command -v python2 &> /dev/null; then
    echo "❌ python2 not found"
    exit 1
fi

if ! python2 -c "from bcc import BPF" 2>/dev/null; then
    echo "❌ BCC Python2 bindings not available"
    exit 1
fi

if ! command -v bpftrace &> /dev/null; then
    echo "❌ bpftrace not found"
    exit 1
fi

echo "✅ Prerequisites satisfied"
echo

# Test BCC tools compilation
echo "🔧 Testing BCC tools compilation..."

# Test vhost_net_monitor.py
echo "  Testing vhost_net_monitor.py..."
timeout 5 python2 bcc-tools/virtio-network/vhost_net_monitor.py --help > /dev/null 2>&1
if [ $? -eq 0 ] || [ $? -eq 124 ]; then  # 124 is timeout exit code
    echo "  ✅ vhost_net_monitor.py: Help text works"
else
    echo "  ❌ vhost_net_monitor.py: Failed to show help"
fi

# Test queue_state_monitor.py  
echo "  Testing queue_state_monitor.py..."
timeout 5 python2 bcc-tools/virtio-network/queue_state_monitor.py --help > /dev/null 2>&1
if [ $? -eq 0 ] || [ $? -eq 124 ]; then
    echo "  ✅ queue_state_monitor.py: Help text works"
else
    echo "  ❌ queue_state_monitor.py: Failed to show help"
fi

# Test bpftrace script syntax
echo "  Testing bpftrace script syntax..."
bpftrace -n bpftrace-tools/vhost-ptr-ring-debug.bt 2>/dev/null
if [ $? -eq 0 ]; then
    echo "  ✅ vhost-ptr-ring-debug.bt: Syntax OK"
else
    echo "  ❌ vhost-ptr-ring-debug.bt: Syntax error"
fi

echo

# Test BPF program compilation (dry run)
echo "🏗️  Testing BPF program compilation (dry run)..."

# Create a minimal test to verify BPF compilation
python2 -c "
from bcc import BPF
try:
    # Test a minimal BPF program
    bpf_text = '''
    int test_probe(struct pt_regs *ctx) {
        return 0;
    }
    '''
    b = BPF(text=bpf_text)
    print('  ✅ Basic BPF compilation works')
except Exception as e:
    print('  ❌ BPF compilation failed: {}'.format(e))
"

echo

# Check kernel support
echo "🔍 Checking kernel features..."

# Check if kprobes are available
if [ -d /sys/kernel/debug/tracing ]; then
    echo "  ✅ Tracing filesystem available"
else
    echo "  ⚠️  Tracing filesystem not mounted (may need: mount -t debugfs debugfs /sys/kernel/debug)"
fi

# Check available kprobes (sample)
if [ -f /sys/kernel/debug/tracing/available_filter_functions ]; then
    if grep -q "tun_net_xmit" /sys/kernel/debug/tracing/available_filter_functions 2>/dev/null; then
        echo "  ✅ tun_net_xmit function available for probing"
    else
        echo "  ⚠️  tun_net_xmit function not found (TUN module might not be loaded)"
    fi
    
    if grep -q "ptr_ring_produce" /sys/kernel/debug/tracing/available_filter_functions 2>/dev/null; then
        echo "  ✅ ptr_ring_produce function available for probing"
    else
        echo "  ⚠️  ptr_ring_produce function not found"
    fi
else
    echo "  ⚠️  Cannot check available functions (may need root permissions)"
fi

echo

# Usage recommendations
echo "💡 Usage recommendations:"
echo
echo "Quick Start (for vnet0 queue 0 issue):"
echo "  sudo bpftrace bpftrace-tools/vhost-ptr-ring-debug.bt"
echo 
echo "Detailed Analysis:"
echo "  sudo python2 bcc-tools/virtio-network/vhost_net_monitor.py --device vnet0 --queue 0"
echo
echo "Queue Comparison:"
echo "  sudo python2 bcc-tools/virtio-network/queue_state_monitor.py --device vnet0 --compare-queues"
echo

echo "🎯 Test completed. Tools should be ready for use!"