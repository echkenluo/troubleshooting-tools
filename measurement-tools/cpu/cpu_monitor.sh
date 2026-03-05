#!/bin/bash


DEFAULT_INTERVAL=5
DEFAULT_LOG_ENABLED=false
DEFAULT_PERF_THRESHOLD=0

TARGET_CPUS=""
MONITOR_CPUS=""
INTERVAL=$DEFAULT_INTERVAL
LOG_ENABLED=$DEFAULT_LOG_ENABLED
LOG_FILE=""
PERF_THRESHOLD=$DEFAULT_PERF_THRESHOLD
PERF_OUTPUT_DIR=""

MAX_PROCESSES_PER_CPU=5

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PERF_STATE_DIR="/tmp/cpu_monitor_$$"

show_help() {
    cat << EOF
CPU Monitor - Real-time CPU Usage and Process Monitoring Tool

Usage: $0 [options]

Options:
  -c, --cpus CPUS            Target CPUs to monitor (comma-separated or ranges), e.g.: 0,1,2 or 0-3,8-11
  -i, --interval INTERVAL    Monitoring interval in seconds (default: 5 seconds)
  -l, --log                  Enable logging to file
  --log-file FILE           Specify log file path
  -t, --threshold PERCENT   CPU usage threshold (%), enables perf profiling when exceeded, 0 disables (default: 0)
  --perf-output DIR         perf output directory (default: /tmp/cpu_monitor_perf)
  -h, --help                Show this help message

Examples:
  $0 -c 0,1,2 -i 5
  $0 -c 0-3,8-11 -i 10 -l
  $0 -c 0,2,4,6 -i 2 --log-file cpu_monitor.log
  $0 -c 0,1 -i 5 -t 80

Features:
  - Real-time CPU usage monitoring
  - Process monitoring per CPU with detailed CPU affinity information
  - Display top ${MAX_PROCESSES_PER_CPU} processes per CPU
  - Automatic perf profiling when CPU usage exceeds threshold
  - Separate perf profiling for each CPU when threshold is exceeded
  - Requires root privileges for perf profiling

EOF
}

log_message() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_line="[$timestamp] $message"
    
    if [ "$LOG_ENABLED" = true ] && [ -n "$LOG_FILE" ]; then
        echo "$log_line" >> "$LOG_FILE"
    else
        echo "$log_line"
    fi
}

error_exit() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

check_perf_available() {
    if ! command -v perf >/dev/null 2>&1; then
        error_exit "perf ， linux-perf  perf "
    fi
    
    if [ "$EUID" -ne 0 ]; then
        local paranoid_level=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "3")
        if [ "$paranoid_level" -gt 1 ]; then
            log_message "${YELLOW}: perf  root  /proc/sys/kernel/perf_event_paranoid${NC}"
        fi
    fi
}

create_perf_output_dir() {
    if [ -z "$PERF_OUTPUT_DIR" ]; then
        PERF_OUTPUT_DIR="/tmp/cpu_monitor_perf_$(date '+%Y%m%d_%H%M%S')"
    fi
    
    if [ ! -d "$PERF_OUTPUT_DIR" ]; then
        mkdir -p "$PERF_OUTPUT_DIR" || error_exit " perf : $PERF_OUTPUT_DIR"
    fi
}

create_perf_state_dir() {
    mkdir -p "$PERF_STATE_DIR" || error_exit ": $PERF_STATE_DIR"
}

is_cpu_perf_running() {
    return 1
}

set_cpu_perf_running() {
    return 0
}

start_parallel_perf_sampling() {
    local cpu_id="$1"
    local duration="$2"
    local timestamp="$3"
    
    local perf_output_file="$PERF_OUTPUT_DIR/perf_cpu${cpu_id}_${timestamp}.data"
    
    (
        sudo perf record --call-graph fp -F 1000 --buildid-all -C "$cpu_id" -o "$perf_output_file" -- sleep "$duration" >/dev/null 2>&1
    ) &
    
    echo $!
}

process_perf_results() {
    local cpu_id="$1"
    local timestamp="$2"
    local cpu_usage="$3"
    local perf_pid="$4"
    
    local perf_output_file="$PERF_OUTPUT_DIR/perf_cpu${cpu_id}_${timestamp}.data"
    local perf_report_file="$PERF_OUTPUT_DIR/perf_cpu${cpu_id}_${timestamp}.txt"
    
    wait "$perf_pid" 2>/dev/null
    
    local usage_float=$(echo "$cpu_usage" | sed 's/,/./g')
    
    if awk "BEGIN {exit !($usage_float >= $PERF_THRESHOLD)}"; then
        if [ -f "$perf_output_file" ]; then
            {
                echo "======== CPU $cpu_id Performance Report - $(date) ========"
                echo " CPU : ${cpu_usage}% (: ${PERF_THRESHOLD}%)"
                echo ": ${INTERVAL} "
                echo ": $perf_output_file"
                echo ""
                echo "======== Top Functions ========"
                perf report -i "$perf_output_file" --stdio --sort=overhead,symbol -n --no-demangle --show-nr-samples 2>/dev/null | head -30
                echo ""
                echo "======== Call Graph (Top 10) ========"
                perf report -i "$perf_output_file" --stdio -g --sort=overhead --no-demangle --call-graph=graph,0.5,caller 2>/dev/null | head -50
                echo ""
                echo "======== Detailed Call Graph with Source Info ========"
                perf report -i "$perf_output_file" --stdio -g --sort=overhead,srcline --call-graph=fractal,0.5 --no-demangle 2>/dev/null | head -30
            } > "$perf_report_file"
            
            log_message "${GREEN} CPU $cpu_id  ${cpu_usage}% ，perf : $perf_report_file${NC}"
        else
            log_message "${RED} CPU $cpu_id perf ${NC}"
        fi
    else
        rm -f "$perf_output_file" 2>/dev/null
        log_message "${BLUE} CPU $cpu_id  ${cpu_usage}%  ${PERF_THRESHOLD}%， perf ${NC}"
    fi
}

should_perf_cpu() {
    local cpu_id="$1"
    
    if [ "$PERF_THRESHOLD" -eq 0 ]; then
        return 1
    fi
    
    if echo " $TARGET_CPUS " | grep -q " $cpu_id "; then
        return 0
    else
        return 1
    fi
}

cleanup_perf_state() {
    if [ -n "$PERF_STATE_DIR" ] && [ -d "$PERF_STATE_DIR" ]; then
        rm -rf "$PERF_STATE_DIR"
    fi
}

parse_cpu_list() {
    local cpu_str="$1"
    local cpus=""
    
    cpu_str=${cpu_str//,/ }
    
    for part in $cpu_str; do
        if [[ "$part" == *-* ]]; then
            local start_cpu=${part%-*}
            local end_cpu=${part#*-}
            for ((i=start_cpu; i<=end_cpu; i++)); do
                cpus="$cpus $i"
            done
        else
            cpus="$cpus $part"
        fi
    done
    
    echo "$cpus"
}

get_cpu_count() {
    local cpu_count=0
    
    if command -v nproc >/dev/null 2>&1; then
        local nproc_count=$(nproc 2>/dev/null || echo "0")
        [ "$nproc_count" -gt "$cpu_count" ] && cpu_count=$nproc_count
    fi
    
    if [ -f /proc/cpuinfo ]; then
        local cpuinfo_count=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null || echo "0")
        [ "$cpuinfo_count" -gt "$cpu_count" ] && cpu_count=$cpuinfo_count
    fi
    
    if command -v lscpu >/dev/null 2>&1; then
        local lscpu_count=$(lscpu 2>/dev/null | grep "^CPU(s):" | awk '{print $2}' || echo "0")
        [ "$lscpu_count" -gt "$cpu_count" ] && cpu_count=$lscpu_count
    fi
    
    if [ -d /sys/devices/system/cpu ]; then
        local sys_count=$(ls -1d /sys/devices/system/cpu/cpu[0-9]* 2>/dev/null | wc -l || echo "0")
        [ "$sys_count" -gt "$cpu_count" ] && cpu_count=$sys_count
    fi
    
    [ "$cpu_count" -eq 0 ] && cpu_count=1
    
    echo "$cpu_count"
}

validate_cpus() {
    local cpus="$1"
    local max_cpu=$(($(get_cpu_count) - 1))
    
    for cpu in $cpus; do
        if ! [[ "$cpu" =~ ^[0-9]+$ ]] || [ "$cpu" -lt 0 ] || [ "$cpu" -gt "$max_cpu" ]; then
            error_exit " CPU  $cpu， CPU : 0-$max_cpu"
        fi
    done
}

get_cpu_topology() {
    local target_cpus="$1"
    local monitored_cpus=""
    
    for cpu in $target_cpus; do
        local siblings_file="/sys/devices/system/cpu/cpu${cpu}/topology/thread_siblings_list"
        if [ -f "$siblings_file" ]; then
            local siblings=$(cat "$siblings_file" 2>/dev/null)
            if [ -n "$siblings" ]; then
                local sibling_cpus=$(parse_cpu_list "$siblings")
                monitored_cpus="$monitored_cpus $sibling_cpus"
            else
                monitored_cpus="$monitored_cpus $cpu"
            fi
        else
            monitored_cpus="$monitored_cpus $cpu"
        fi
    done
    
    echo "$monitored_cpus" | tr ' ' '\n' | sort -n | uniq | tr '\n' ' '
}

read_cpu_stats() {
    local cpu_id="$1"
    
    if [ "$cpu_id" = "all" ]; then
        grep "^cpu " /proc/stat | awk '{print $2, $3, $4, $5, $6, $7, $8}'
    else
        grep "^cpu${cpu_id} " /proc/stat | awk '{print $2, $3, $4, $5, $6, $7, $8}'
    fi
}

calculate_cpu_usage() {
    local prev_stats="$1"
    local curr_stats="$2"
    
    if [ -z "$prev_stats" ] || [ -z "$curr_stats" ]; then
        echo "0.00"
        return
    fi
    
    read -r prev_user prev_nice prev_system prev_idle prev_iowait prev_irq prev_softirq <<< "$prev_stats"
    read -r curr_user curr_nice curr_system curr_idle curr_iowait curr_irq curr_softirq <<< "$curr_stats"
    
    local prev_idle_total=$((prev_idle + prev_iowait))
    local curr_idle_total=$((curr_idle + curr_iowait))
    
    local prev_non_idle=$((prev_user + prev_nice + prev_system + prev_irq + prev_softirq))
    local curr_non_idle=$((curr_user + curr_nice + curr_system + curr_irq + curr_softirq))
    
    local prev_total=$((prev_idle_total + prev_non_idle))
    local curr_total=$((curr_idle_total + curr_non_idle))
    
    local total_diff=$((curr_total - prev_total))
    local idle_diff=$((curr_idle_total - prev_idle_total))
    
    if [ "$total_diff" -eq 0 ]; then
        echo "0.00"
    else
        echo "$total_diff $idle_diff" | awk '{printf "%.2f", 100 * ($1 - $2) / $1}'
    fi
}

read_process_cpu_time() {
    local pid="$1"
    local tid="$2"
    
    local stat_file="/proc/$pid/stat"
    if [ "$tid" != "$pid" ] && [ -f "/proc/$pid/task/$tid/stat" ]; then
        stat_file="/proc/$pid/task/$tid/stat"
    fi
    
    if [ ! -f "$stat_file" ]; then
        echo ""
        return
    fi
    
    awk '{print $14, $15}' "$stat_file" 2>/dev/null
}

get_system_hz() {
    getconf CLK_TCK 2>/dev/null || echo "100"
}

calculate_process_cpu_usage() {
    local prev_cpu_time="$1"
    local curr_cpu_time="$2"
    local time_interval="$3"
    
    if [ -z "$prev_cpu_time" ] || [ -z "$curr_cpu_time" ] || [ -z "$time_interval" ]; then
        echo "0.00"
        return
    fi
    
    read -r prev_utime prev_stime <<< "$prev_cpu_time"
    read -r curr_utime curr_stime <<< "$curr_cpu_time"
    
    local utime_diff=$((curr_utime - prev_utime))
    local stime_diff=$((curr_stime - prev_stime))
    local total_time_diff=$((utime_diff + stime_diff))
    
    if [ "$total_time_diff" -le 0 ]; then
        echo "0.00"
        return
    fi
    
    local hz=$(get_system_hz)
    
    echo "$total_time_diff $hz $time_interval" | awk '{printf "%.2f", ($1 / $2) / $3 * 100}'
}

cache_all_processes() {
    local cache_file="/tmp/cpu_monitor_$$_ps_cache"
    ps -eLo pid,tid,psr,comm --no-headers > "$cache_file" 2>/dev/null
}

collect_processes_on_cpu_start() {
    local target_cpu="$1"
    local temp_file="/tmp/cpu_monitor_$$_${target_cpu}_start"
    local cache_file="/tmp/cpu_monitor_$$_ps_cache"

    # Use cached ps output if available, otherwise fallback to direct ps call
    local process_list_1
    if [ -f "$cache_file" ]; then
        process_list_1=$(awk -v cpu="$target_cpu" '$3 == cpu {print $1, $2, $4}' "$cache_file")
    else
        process_list_1=$(ps -eLo pid,tid,psr,comm --no-headers | awk -v cpu="$target_cpu" '$3 == cpu {print $1, $2, $4}')
    fi

    if [ -z "$process_list_1" ]; then
        return
    fi

    > "$temp_file"

    while read -r pid tid comm; do
        local cpu_time=$(read_process_cpu_time "$pid" "$tid")
        if [ -n "$cpu_time" ]; then
            local real_comm="$comm"
            if [ "$comm" = "CPU" ] || [ "$comm" = "kworker" ] || [[ "$comm" =~ ^kworker ]]; then
                if [ -f "/proc/$pid/cmdline" ]; then
                    local cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -c 30)
                    if [ -n "$cmdline" ] && [ "$cmdline" != " " ]; then
                        local main_cmd=$(echo "$cmdline" | awk '{print $1}' | sed 's/.*\///')
                        if [ -n "$main_cmd" ] && [ "$main_cmd" != "" ]; then
                            real_comm="$main_cmd"
                        fi
                    fi
                fi
            fi
            echo "${pid}|${tid}|${cpu_time}|${real_comm}" >> "$temp_file"
        fi
    done <<< "$process_list_1"
}

cleanup_ps_cache() {
    local cache_file="/tmp/cpu_monitor_$$_ps_cache"
    rm -f "$cache_file" 2>/dev/null
}

calculate_processes_on_cpu_end() {
    local target_cpu="$1"
    local count=${2:-$MAX_PROCESSES_PER_CPU}
    local time_interval=${3:-$INTERVAL}
    local temp_file="/tmp/cpu_monitor_$$_${target_cpu}_start"
    
    if [ ! -f "$temp_file" ]; then
        return
    fi
    
    local results=""
    while IFS='|' read -r pid tid prev_cpu_time comm; do
        local curr_cpu_time=$(read_process_cpu_time "$pid" "$tid")
        if [ -n "$curr_cpu_time" ] && [ -n "$prev_cpu_time" ]; then
            local cpu_usage=$(calculate_process_cpu_usage "$prev_cpu_time" "$curr_cpu_time" "$time_interval")
            if [ -n "$cpu_usage" ] && awk "BEGIN {exit !($cpu_usage > 0.1 && $cpu_usage <= 100)}"; then
                results="${results}${cpu_usage} $pid $tid $comm"$'\n'
            fi
        fi
    done < "$temp_file"
    
    rm -f "$temp_file"
    
    if [ -n "$results" ]; then
        echo "$results" | sort -nr | head -n "$count" | while read -r cpu_usage pid tid comm; do
            printf "%6d %6d %3d %5.1f%% %-20s\n" "$pid" "$tid" "$target_cpu" "$cpu_usage" "$comm"
        done
    fi
}

calculate_total_cpu_usage() {
    local prev_total_stats="$1"
    local curr_total_stats="$2"
    
    local total_cpu_usage=$(calculate_cpu_usage "$prev_total_stats" "$curr_total_stats")
    echo "$total_cpu_usage"
}

format_report() {
    local monitored_cpus="$1"
    local -A cpu_usage
    local -A perf_pids
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    
    declare -A prev_stats curr_stats
    
    local prev_total_stats=$(read_cpu_stats "all")
    for cpu in $monitored_cpus; do
        prev_stats[$cpu]=$(read_cpu_stats "$cpu")
    done

    # Cache ps output once for all CPUs to improve performance
    cache_all_processes

    for cpu in $monitored_cpus; do
        collect_processes_on_cpu_start "$cpu"
    done

    # Clean up ps cache after use
    cleanup_ps_cache
    
    if [ "$PERF_THRESHOLD" -gt 0 ]; then
        log_message "${YELLOW} CPU perf  (${INTERVAL}s)${NC}"
        for cpu in $monitored_cpus; do
            if should_perf_cpu "$cpu"; then
                local perf_pid=$(start_parallel_perf_sampling "$cpu" "$INTERVAL" "$timestamp")
                perf_pids[$cpu]="$perf_pid"
            fi
        done
    fi
    
    sleep "$INTERVAL"
    
    local curr_total_stats=$(read_cpu_stats "all")
    for cpu in $monitored_cpus; do
        curr_stats[$cpu]=$(read_cpu_stats "$cpu")
        cpu_usage[$cpu]=$(calculate_cpu_usage "${prev_stats[$cpu]}" "${curr_stats[$cpu]}")
    done
    
    if [ "$PERF_THRESHOLD" -gt 0 ]; then
        for cpu in $monitored_cpus; do
            if should_perf_cpu "$cpu" && [ -n "${perf_pids[$cpu]}" ]; then
                process_perf_results "$cpu" "$timestamp" "${cpu_usage[$cpu]}" "${perf_pids[$cpu]}"
            fi
        done
    fi
    
    local total_cpu_usage=$(calculate_total_cpu_usage "$prev_total_stats" "$curr_total_stats")
    
    echo "======== CPU  - $(date '+%H:%M:%S') ========"
    
    printf " CPU : %.1f%%\n" "$total_cpu_usage"
    echo ""
    
    for target_cpu in $TARGET_CPUS; do
        local cpu_group="$target_cpu"
        local siblings_file="/sys/devices/system/cpu/cpu${target_cpu}/topology/thread_siblings_list"
        if [ -f "$siblings_file" ]; then
            local siblings=$(cat "$siblings_file" 2>/dev/null)
            if [ -n "$siblings" ]; then
                cpu_group=$(parse_cpu_list "$siblings")
            fi
        fi
        
        echo " CPU $target_cpu  [$cpu_group]:"
        
        for cpu in $cpu_group; do
            local usage="${cpu_usage[$cpu]:-0.00}"
            
            local cpu_label=""
            local perf_indicator=""
            if echo " $TARGET_CPUS " | grep -q " $cpu "; then
                cpu_label=" ${GREEN}[]${NC}"
                if [ "$PERF_THRESHOLD" -gt 0 ]; then
                    local usage_float=$(echo "$usage" | sed 's/,/./g')
                    if awk "BEGIN {exit !($usage_float >= $PERF_THRESHOLD)}"; then
                        perf_indicator=" ${GREEN}[PERF]${NC}"
                    else
                        perf_indicator=" ${BLUE}[PERF]${NC}"
                    fi
                fi
            fi
            
            printf "  CPU %2d: %6.1f%%%s%s - / (${INTERVAL}sCPU):\n" "$cpu" "$usage" "$perf_indicator" "$cpu_label"
            printf "    %6s %6s %3s %5s %-20s\n" "PID" "TID" "CPU" "%CPU" "COMMAND"
            printf "    %6s %6s %3s %5s %-20s\n" "------" "------" "---" "-----" "--------------------"
            
            local process_list=$(calculate_processes_on_cpu_end "$cpu" "$MAX_PROCESSES_PER_CPU" "$INTERVAL")
            if [ -n "$process_list" ]; then
                echo "$process_list" | sed 's/^/    /'
            else
                echo "    "
            fi
            echo ""
        done
    done
}

monitor_cycle() {
    local monitored_cpus="$1"
    # Call format_report directly and pipe output through log_message
    # This avoids waiting for the entire report to complete before showing output
    format_report "$monitored_cpus" | while IFS= read -r line; do
        log_message "$line"
    done
}

start_monitoring() {
    local monitored_cpus="$1"
    
    log_message "================================================================================"
    log_message "CPU "
    log_message " CPU: [$(echo $TARGET_CPUS | tr ' ' ',')]"
    log_message " CPU: [$(echo $monitored_cpus | tr ' ' ',')]"
    log_message ": $INTERVAL "
    log_message "CPU: $INTERVAL "
    log_message "CPU: $MAX_PROCESSES_PER_CPU"
    if [ "$LOG_ENABLED" = true ] && [ -n "$LOG_FILE" ]; then
        log_message ": $LOG_FILE"
    fi
    if [ "$PERF_THRESHOLD" -gt 0 ]; then
        log_message "Perf : $PERF_THRESHOLD%"
        log_message "Perf : $PERF_OUTPUT_DIR"
        log_message " Perf : ，，CPU"
    else
        log_message "Perf : "
    fi
    log_message "================================================================================"
    
    trap 'log_message ""; log_message "，..."; cleanup_perf_state; log_message "CPU "; exit 0' INT TERM
    
    while true; do
        local start_time=$(date +%s)
        
        monitor_cycle "$monitored_cpus"
        
        local elapsed=$(($(date +%s) - start_time))
        local sleep_time=$((INTERVAL - elapsed))
        
        if [ "$sleep_time" -gt 0 ]; then
            sleep "$sleep_time"
        fi
    done
}

main() {
    if ! command -v getopt >/dev/null 2>&1; then
        error_exit " getopt "
    fi
    
    local parsed_args
    parsed_args=$(getopt -o c:i:lt:h --long cpus:,interval:,log,log-file:,threshold:,perf-output:,help -n "$0" -- "$@" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        show_help
        exit 1
    fi
    
    eval set -- "$parsed_args"
    
    while true; do
        case "$1" in
            -c|--cpus)
                TARGET_CPUS=$(parse_cpu_list "$2")
                shift 2
                ;;
            -i|--interval)
                INTERVAL="$2"
                shift 2
                ;;
            -l|--log)
                LOG_ENABLED=true
                shift
                ;;
            --log-file)
                LOG_ENABLED=true
                LOG_FILE="$2"
                shift 2
                ;;
            -t|--threshold)
                PERF_THRESHOLD="$2"
                shift 2
                ;;
            --perf-output)
                PERF_OUTPUT_DIR="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            --)
                shift
                break
                ;;
            *)
                error_exit ": $1"
                ;;
        esac
    done
    
    if [ -z "$TARGET_CPUS" ]; then
        error_exit " CPU  (-c )"
    fi
    
    if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [ "$INTERVAL" -lt 1 ]; then
        error_exit ""
    fi
    
    if ! [[ "$PERF_THRESHOLD" =~ ^[0-9]+$ ]] || [ "$PERF_THRESHOLD" -lt 0 ] || [ "$PERF_THRESHOLD" -gt 100 ]; then
        error_exit "perf  0-100 "
    fi
    
    validate_cpus "$TARGET_CPUS"
    
    if [ "$LOG_ENABLED" = true ] && [ -z "$LOG_FILE" ]; then
        LOG_FILE="cpu_monitor_$(date '+%Y%m%d_%H%M%S').log"
    fi
    
    if [ "$PERF_THRESHOLD" -gt 0 ]; then
        check_perf_available
        create_perf_output_dir
        create_perf_state_dir
    fi
    
    MONITOR_CPUS=$(get_cpu_topology "$TARGET_CPUS")
    
    start_monitoring "$MONITOR_CPUS"
}

main "$@" 