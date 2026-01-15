#!/bin/bash
# vhost worker scheduling configuration check script
# Usage: ./vhost_sched_config_check.sh <vnet_interface>
# Example: ./vhost_sched_config_check.sh vnet502

set -e

VNET_IFACE="${1:-vnet0}"

echo "========================================"
echo "vhost Worker Scheduling Configuration Check"
echo "========================================"
echo "Target interface: $VNET_IFACE"
echo "Timestamp: $(date)"
echo "Hostname: $(hostname)"
echo "Kernel: $(uname -r)"
echo ""

# Find QEMU process for this vnet interface
echo "=== 1. QEMU Process and vhost Worker Info ==="
QEMU_PID=$(ps aux | grep qemu | grep "$VNET_IFACE" | grep -v grep | awk '{print $2}' | head -1)
if [ -z "$QEMU_PID" ]; then
    echo "WARNING: Cannot find QEMU process for $VNET_IFACE"
    QEMU_PID=$(pgrep -f "qemu.*$VNET_IFACE" 2>/dev/null | head -1)
fi

if [ -n "$QEMU_PID" ]; then
    echo "QEMU PID: $QEMU_PID"
    echo ""
    echo "QEMU command line (network related):"
    cat /proc/$QEMU_PID/cmdline 2>/dev/null | tr '\0' '\n' | grep -E 'netdev|vhost|tap' || echo "N/A"
    echo ""
fi

# Find vhost worker threads
echo "=== 2. vhost Worker Threads ==="
VHOST_PIDS=$(ps -eLf | grep -E "vhost-" | grep -v grep | awk '{print $4}')
if [ -z "$VHOST_PIDS" ]; then
    echo "WARNING: No vhost worker threads found"
else
    echo "vhost worker threads:"
    ps -eLo pid,tid,comm,psr,pri,ni,stat,wchan:20 | head -1
    ps -eLo pid,tid,comm,psr,pri,ni,stat,wchan:20 | grep -E "vhost-"
    echo ""
    echo "vhost worker CPU affinity:"
    for pid in $VHOST_PIDS; do
        comm=$(cat /proc/$pid/comm 2>/dev/null || echo "unknown")
        affinity=$(taskset -p $pid 2>/dev/null | awk '{print $NF}')
        echo "  TID $pid ($comm): affinity mask = $affinity"
    done
fi
echo ""

# Find vCPU threads
echo "=== 3. vCPU Threads ==="
if [ -n "$QEMU_PID" ]; then
    echo "vCPU threads for QEMU $QEMU_PID:"
    ps -eLo pid,tid,comm,psr,pri,ni,stat,wchan:20 | head -1
    ps -eLo pid,tid,comm,psr,pri,ni,stat,wchan:20 | grep "^$QEMU_PID" | grep -E "CPU|qemu"
    echo ""
    echo "vCPU CPU affinity:"
    for tid in $(ps -eLo tid,comm | grep "^" | awk '{print $1}' | xargs -I{} sh -c "cat /proc/{}/comm 2>/dev/null | grep -q CPU && echo {}"); do
        affinity=$(taskset -p $tid 2>/dev/null | awk '{print $NF}')
        echo "  TID $tid: affinity mask = $affinity"
    done 2>/dev/null || echo "N/A"
fi
echo ""

# NUMA topology
echo "=== 4. NUMA Topology ==="
if command -v numactl &> /dev/null; then
    numactl --hardware 2>/dev/null || echo "numactl not available or failed"
else
    echo "numactl not installed"
    echo "Checking /sys for NUMA info:"
    ls -la /sys/devices/system/node/ 2>/dev/null || echo "N/A"
fi
echo ""

# C-state configuration
echo "=== 5. CPU C-state Configuration ==="
echo "C-state status (first CPU as example):"
if [ -d /sys/devices/system/cpu/cpu0/cpuidle ]; then
    for state in /sys/devices/system/cpu/cpu0/cpuidle/state*; do
        if [ -d "$state" ]; then
            name=$(cat $state/name 2>/dev/null || echo "N/A")
            desc=$(cat $state/desc 2>/dev/null || echo "N/A")
            latency=$(cat $state/latency 2>/dev/null || echo "N/A")
            disable=$(cat $state/disable 2>/dev/null || echo "N/A")
            echo "  $(basename $state): name=$name, latency=${latency}us, disabled=$disable"
        fi
    done
else
    echo "cpuidle not available in sysfs"
fi
echo ""

echo "Kernel cmdline (idle/cstate related):"
cat /proc/cmdline | tr ' ' '\n' | grep -iE 'idle|cstate|intel_idle|processor|nohz' || echo "No idle-related parameters found"
echo ""

# P-state / CPU frequency
echo "=== 6. CPU Frequency / P-state ==="
echo "CPU frequency governor:"
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "N/A"
echo "Current frequency (first CPU):"
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo "N/A"
echo "Available frequencies:"
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies 2>/dev/null || echo "N/A"
echo ""

# vhost-net module parameters
echo "=== 7. vhost-net Module Parameters ==="
if [ -d /sys/module/vhost_net/parameters ]; then
    echo "vhost_net module parameters:"
    for param in /sys/module/vhost_net/parameters/*; do
        if [ -f "$param" ]; then
            echo "  $(basename $param) = $(cat $param 2>/dev/null || echo 'N/A')"
        fi
    done
else
    echo "vhost_net module parameters not found in sysfs"
fi
echo ""

echo "vhost module parameters:"
if [ -d /sys/module/vhost/parameters ]; then
    for param in /sys/module/vhost/parameters/*; do
        if [ -f "$param" ]; then
            echo "  $(basename $param) = $(cat $param 2>/dev/null || echo 'N/A')"
        fi
    done
else
    echo "vhost module parameters not found in sysfs"
fi
echo ""

# Scheduler configuration
echo "=== 8. Scheduler Configuration ==="
echo "Scheduler type:"
cat /sys/kernel/debug/sched/features 2>/dev/null | head -5 || echo "N/A (need root or debug fs)"
echo ""
echo "sched_latency_ns:"
cat /proc/sys/kernel/sched_latency_ns 2>/dev/null || echo "N/A"
echo "sched_min_granularity_ns:"
cat /proc/sys/kernel/sched_min_granularity_ns 2>/dev/null || echo "N/A"
echo "sched_wakeup_granularity_ns:"
cat /proc/sys/kernel/sched_wakeup_granularity_ns 2>/dev/null || echo "N/A"
echo ""

# CPU isolation
echo "=== 9. CPU Isolation ==="
echo "Kernel cmdline (isolation related):"
cat /proc/cmdline | tr ' ' '\n' | grep -iE 'isolcpus|nohz_full|rcu_nocbs' || echo "No isolation parameters found"
echo ""

# IRQ affinity for network interfaces
echo "=== 10. Network IRQ Affinity ==="
echo "IRQs for $VNET_IFACE and related interfaces:"
for irq in $(grep -l "virtio\|vhost\|eth\|ens\|enp" /proc/irq/*/smp_affinity 2>/dev/null | cut -d'/' -f4); do
    affinity=$(cat /proc/irq/$irq/smp_affinity 2>/dev/null)
    action=$(cat /proc/irq/$irq/actions 2>/dev/null | head -1 | awk '{print $1}')
    echo "  IRQ $irq ($action): smp_affinity = $affinity"
done 2>/dev/null | head -20 || echo "N/A"
echo ""

# Kernel config (if available)
echo "=== 11. Kernel Configuration (key options) ==="
if [ -f /proc/config.gz ]; then
    echo "From /proc/config.gz:"
    zcat /proc/config.gz 2>/dev/null | grep -E "CONFIG_VHOST|CONFIG_PREEMPT|CONFIG_NO_HZ|CONFIG_HIGH_RES" | head -20
elif [ -f /boot/config-$(uname -r) ]; then
    echo "From /boot/config-$(uname -r):"
    grep -E "CONFIG_VHOST|CONFIG_PREEMPT|CONFIG_NO_HZ|CONFIG_HIGH_RES" /boot/config-$(uname -r) 2>/dev/null | head -20
else
    echo "Kernel config not available"
fi
echo ""

echo "========================================"
echo "Configuration check completed"
echo "========================================"
