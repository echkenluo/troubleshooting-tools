#!/bin/bash


DEFAULT_PROCESS="ovs-vswitchd"
DEFAULT_INTERVAL=1
DEFAULT_LOG_FILE="sched_latency.log"
DEFAULT_MEASUREMENT_PERIOD=1
DEFAULT_VERBOSE=false
DEFAULT_WORK_DIR="/tmp/sched_monitor_$$"

show_help() {
    echo "Scheduler Latency Monitor"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -p, --process PROCESS     Target process name to monitor (default: $DEFAULT_PROCESS)"
    echo "  -t, --period SECONDS      Measurement period for perf profiling in seconds (default: $DEFAULT_MEASUREMENT_PERIOD)"
    echo "  -i, --interval SECONDS     Monitoring interval in seconds (default: $DEFAULT_INTERVAL)"
    echo "  -l, --log FILE            Log file path (default: $DEFAULT_LOG_FILE)"
    echo "  -v, --verbose             Enable verbose output (default: disabled)"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -p ovs-vswitchd -t 1 -i 1"
    echo "  $0 --process qemu-kvm --period 2 --interval 1"
    echo "  $0 -t 1 -i 0.5 -v"
    exit 0
}

log_with_timestamp() {
    local message="$1"
    local to_stdout="${2:-false}"
    local log_line="[$(date '+%Y-%m-%d %H:%M:%S.%3N')] $message"
    
    if [ "$to_stdout" = "true" ]; then
        echo "$log_line"
    fi
}

check_process_exists() {
    local process_name="$1"
    local verbose="$2"
    local pid=$(pidof "$process_name")
    if [ -z "$pid" ]; then
        log_with_timestamp "Error: Process '$process_name' not found" "$verbose"
        return 1
    else
        log_with_timestamp "Found process '$process_name', PID: $pid" "$verbose"
        return 0
    fi
}

check_perf_available() {
    local verbose="$1"
    if ! command -v perf >/dev/null 2>&1; then
        log_with_timestamp ": perf，linux-tools" "$verbose"
        exit 1
    fi
    
    if ! sudo perf --version >/dev/null 2>&1; then
        log_with_timestamp ": sudoperf" "$verbose"
        exit 1
    fi
}

sampling_process() {
    local process_name="$1"
    local interval="$2"
    local measurement_period="$3"
    local work_dir="$4"
    local verbose="$5"
    
    local sample_count=0
    local next_time=$(date +%s.%N)
    
    log_with_timestamp ": =${interval}, =${measurement_period}" "$verbose"
    
    while [ -f "$work_dir/run_flag" ]; do
        sample_count=$((sample_count + 1))
        
        if ! check_process_exists "$process_name" false; then
            log_with_timestamp "，" "$verbose"
            break
        fi
        
        local pid=$(pidof "$process_name")
        local timestamp=$(date '+%Y%m%d_%H%M%S_%3N')
        local start_epoch=$(date +%s.%N)
        local perf_data_file="$work_dir/perf_${timestamp}_${pid}_${sample_count}.data"
        local meta_file="${perf_data_file}.meta"
        
        {
            echo "timestamp=$timestamp"
            echo "start_epoch=$start_epoch"
            echo "process_name=$process_name"
            echo "pid=$pid"
            echo "sample_count=$sample_count"
            echo "measurement_period=$measurement_period"
            echo "status=recording"
        } > "$meta_file"
        
        log_with_timestamp "${sample_count} -> $perf_data_file" "$verbose"
        
        {
            if sudo perf sched record -p "$pid" -o "$perf_data_file" -- sleep "$measurement_period" 2>/dev/null; then
                sed -i 's/status=recording/status=completed/' "$meta_file"
                log_with_timestamp "${sample_count}" "$verbose"
            else
                sed -i 's/status=recording/status=failed/' "$meta_file"
                log_with_timestamp "${sample_count}" "$verbose"
            fi
        } &
        
        next_time=$(echo "$next_time + $interval" | bc -l)
        local current_time=$(date +%s.%N)
        local sleep_time=$(echo "$next_time - $current_time" | bc -l)
        
        if (( $(echo "$sleep_time > 0" | bc -l) )); then
            sleep "$sleep_time"
        else
            log_with_timestamp ": ${sample_count}$(echo "0 - $sleep_time" | bc -l)" "$verbose"
            next_time=$(date +%s.%N)
        fi
    done
    
    log_with_timestamp "，perf..." "$verbose"
    wait
}

processing_process() {
    local log_file="$1"
    local work_dir="$2"
    local verbose="$3"
    local delay_cycles="$4"
    
    log_with_timestamp "，${delay_cycles}" "$verbose"
    
    sleep "$delay_cycles"

    {
        echo "========================================"
        echo "Scheduler Latency Monitoring Log"
        echo "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "========================================"
    } >> "$log_file"
    
    local processed_count=0
    
    while [ -f "$work_dir/run_flag" ] || [ -n "$(find "$work_dir" -name "*.meta" -type f 2>/dev/null)" ]; do
        local found_file=false
        
        shopt -s nullglob
        for meta_file in "$work_dir"/*.meta; do
            [ -f "$meta_file" ] || continue
            
            local status=$(grep "status=" "$meta_file" | cut -d'=' -f2)
            
            if [ "$status" = "completed" ]; then
                local data_file="${meta_file%.meta}"
                
                if [ -f "$data_file" ]; then
                    found_file=true
                    processed_count=$((processed_count + 1))
                    
                    local timestamp=$(grep "timestamp=" "$meta_file" | cut -d'=' -f2)
                    local process_name=$(grep "process_name=" "$meta_file" | cut -d'=' -f2)
                    local pid=$(grep "pid=" "$meta_file" | cut -d'=' -f2)
                    local sample_count=$(grep "sample_count=" "$meta_file" | cut -d'=' -f2)
                    local measurement_period=$(grep "measurement_period=" "$meta_file" | cut -d'=' -f2)
                    local start_epoch=$(grep "start_epoch=" "$meta_file" | cut -d'=' -f2)
                    
                    local formatted_time=$(echo "$timestamp" | sed 's/\([0-9]\{4\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)_\([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)_\([0-9]\{3\}\)/\1-\2-\3 \4:\5:\6.\7/')
                    
                    log_with_timestamp "${processed_count}: $data_file" "$verbose"
                    
                    {
                        echo ""
                        echo "====================  #${sample_count} ===================="
                        echo ": $formatted_time"
                        echo ": $process_name"
                        echo "PID: $pid"
                        echo ": ${measurement_period}"
                        echo ": $sample_count"
                        echo "=============================================================="
                        echo ""
                    } >> "$log_file"
                    
                    if sudo perf sched latency -i "$data_file" >> "$log_file" 2>/dev/null; then
                        log_with_timestamp ": ${sample_count}" "$verbose"
                    else
                        log_with_timestamp ": perf sched latency: ${sample_count}" "$verbose"
                        echo ": perf sched latency" >> "$log_file"
                    fi
                    
                    {
                        echo ""
                        echo "==================== End of Sample #${sample_count} ===================="
                        echo ""
                    } >> "$log_file"
                    
                    rm -f "$data_file" "$meta_file"
                    
                fi
            elif [ "$status" = "failed" ]; then
                local data_file="${meta_file%.meta}"
                rm -f "$data_file" "$meta_file"
                log_with_timestamp "" "$verbose"
            fi
        done
        
        if [ "$found_file" = "false" ]; then
            sleep 0.1
        fi
    done
    
    log_with_timestamp "，${processed_count}" "$verbose"
}

cleanup_and_exit() {
    local work_dir="$1"
    local verbose="$2"
    
    log_with_timestamp "，..." "$verbose"
    
    rm -f "$work_dir/run_flag"
    
    log_with_timestamp "..." "$verbose"
    wait
    
    if [ -d "$work_dir" ]; then
        rm -rf "$work_dir"
        log_with_timestamp ": $work_dir" "$verbose"
    fi
    
    log_with_timestamp "" "$verbose"
    exit 0
}

main() {
    local process_name="$DEFAULT_PROCESS"
    local interval="$DEFAULT_INTERVAL"
    local log_file="$DEFAULT_LOG_FILE"
    local measurement_period="$DEFAULT_MEASUREMENT_PERIOD"
    local verbose="$DEFAULT_VERBOSE"
    local work_dir="$DEFAULT_WORK_DIR"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--process)
                process_name="$2"
                shift 2
                ;;
            -t|--period)
                measurement_period="$2"
                shift 2
                ;;
            -i|--interval)
                interval="$2"
                shift 2
                ;;
            -l|--log)
                log_file="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose="true"
                shift
                ;;
            -h|--help)
                show_help
                ;;
            *)
                echo ": $1"
                echo " $0 --help "
                exit 1
                ;;
        esac
    done
    
    if ! command -v bc >/dev/null 2>&1; then
        echo ": bc，bc"
        exit 1
    fi
    
    if ! [[ "$interval" =~ ^[0-9]*\.?[0-9]+$ ]]; then
        echo ": "
        exit 1
    fi
    
    if ! [[ "$measurement_period" =~ ^[0-9]*\.?[0-9]+$ ]]; then
        echo ": "
        exit 1
    fi
    
    check_perf_available "$verbose"
    
    mkdir -p "$work_dir"
    if [ ! -d "$work_dir" ]; then
        log_with_timestamp ":  $work_dir" "$verbose"
        exit 1
    fi
    
    touch "$work_dir/run_flag"
    
    trap "cleanup_and_exit '$work_dir' '$verbose'" SIGINT SIGTERM
    
    log_with_timestamp "" "$verbose"
    log_with_timestamp ": $process_name" "$verbose"
    log_with_timestamp ": ${interval}" "$verbose"
    log_with_timestamp ": ${measurement_period}" "$verbose"
    log_with_timestamp ": $log_file" "$verbose"
    log_with_timestamp ": $work_dir" "$verbose"
    log_with_timestamp " Ctrl+C " "$verbose"
    
    local delay_cycles=$(echo "$measurement_period * 1.5" | bc -l)
    
    processing_process "$log_file" "$work_dir" "$verbose" "$delay_cycles" &
    local processor_pid=$!
    
    sampling_process "$process_name" "$interval" "$measurement_period" "$work_dir" "$verbose"
    
    wait $processor_pid
    
    cleanup_and_exit "$work_dir" "$verbose"
}

main "$@" 