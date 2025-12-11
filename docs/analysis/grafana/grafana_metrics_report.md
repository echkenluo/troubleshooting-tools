# Grafana Metrics Complete Report

**Server**: http://192.168.79.79/grafana
**Grafana Version**: 9.0.9
**Authentication**:

- Traefik Basic Auth: `o11y:HC!r0cks`
- Grafana Login: `admin:HC!r0cks`

---

## Data Sources Overview

| ID | Name                                      | Type       | Backend URL                        | Default       |
| -- | ----------------------------------------- | ---------- | ---------------------------------- | ------------- |
| 1  | VictoriaMetrics                           | Prometheus | http://victoriametrics:8428        | No            |
| 2  | Clickhouse                                | ClickHouse | clickhouse:9000                    | No            |
| 3  | Loki                                      | Loki       | http://loki:3100                   | No            |
| 4  | configcenter                              | JSON API   | http://configcenter:9901           | No            |
| 5  | alertmanager-extension                    | JSON API   | http://alertmanager-extension:9903 | No            |
| 6  | notifycenter                              | JSON API   | http://notifycenter:9905           | No            |
| 7  | alert-query-api                           | JSON API   | http://alertmanager-extension:9903 | No            |
| 8  | **traffic-visualization-query-api** | JSON API   | http://queryloader:8011            | **Yes** |

---

## Part 1: VictoriaMetrics Metrics (Total: 5641)

### Category Summary

| Category             | Count | Description                 |
| -------------------- | ----- | --------------------------- |
| ClickHouse           | 1835  | ClickHouse database metrics |
| Ceph/ZBS Storage     | 966   | Distributed storage system  |
| Other                | 969   | Miscellaneous metrics       |
| Node Exporter        | 364   | Linux system metrics        |
| PostgreSQL           | 335   | PostgreSQL database         |
| VictoriaMetrics      | 331   | Time series database        |
| Loki                 | 226   | Log aggregation system      |
| Go Runtime           | 127   | Go application runtime      |
| Container (cAdvisor) | 128   | Container resource usage    |
| Host Metrics         | 104   | Host-level metrics          |
| ELF (VM)             | 69    | Virtual machine metrics     |
| Process              | 41    | Process-level metrics       |
| Prometheus           | 34    | Prometheus self-monitoring  |
| Vector/Log           | 33    | Vector log collector        |
| Kubernetes           | 31    | K8s components              |
| Traefik              | 20    | Reverse proxy               |
| containerd           | 18    | Container runtime           |
| Scrape Metrics       | 6     | Scrape status               |
| Alerts & Status      | 4     | Alert state                 |

---

### 1. Node Exporter Metrics (364)

#### 1.1 Network (36 metrics)

```
node_network_receive_bytes_total
node_network_receive_packets_total
node_network_receive_errs_total
node_network_receive_drop_total
node_network_transmit_bytes_total
node_network_transmit_packets_total
node_network_transmit_errs_total
node_network_transmit_drop_total
node_network_carrier
node_network_up
node_network_speed_bytes
node_network_mtu_bytes
node_network_info
... (and 23 more)
```

#### 1.2 Netstat TCP/UDP (42 metrics)

```
node_netstat_Tcp_CurrEstab
node_netstat_Tcp_InSegs
node_netstat_Tcp_OutSegs
node_netstat_Tcp_RetransSegs
node_netstat_Tcp_InErrs
node_netstat_Tcp_OutRsts
node_netstat_Tcp_ActiveOpens
node_netstat_Tcp_PassiveOpens
node_netstat_TcpExt_ListenDrops
node_netstat_TcpExt_ListenOverflows
node_netstat_TcpExt_TCPTimeouts
node_netstat_TcpExt_TCPSynRetrans
node_netstat_TcpExt_TCPRcvQDrop
node_netstat_Udp_InDatagrams
node_netstat_Udp_OutDatagrams
node_netstat_Udp_InErrors
node_netstat_Udp_RcvbufErrors
node_netstat_Udp_SndbufErrors
... (and 24 more)
```

#### 1.3 Socket Stats (14 metrics)

```
node_sockstat_TCP_inuse
node_sockstat_TCP_alloc
node_sockstat_TCP_orphan
node_sockstat_TCP_tw
node_sockstat_UDP_inuse
node_sockstat_sockets_used
... (and 8 more)
```

#### 1.4 Memory (56 metrics)

```
node_memory_MemTotal_bytes
node_memory_MemFree_bytes
node_memory_MemAvailable_bytes
node_memory_Buffers_bytes
node_memory_Cached_bytes
node_memory_Active_bytes
node_memory_Inactive_bytes
node_memory_SwapTotal_bytes
node_memory_SwapFree_bytes
... (and 47 more)
```

#### 1.5 CPU (14 metrics)

```
node_cpu_seconds_total
node_cpu_frequency_hertz
node_cpu_scaling_frequency_hertz
node_cpu_core_throttles_total
node_cpu_online
... (and 9 more)
```

#### 1.6 Disk/Filesystem (36 metrics)

```
node_disk_read_bytes_total
node_disk_written_bytes_total
node_disk_reads_completed_total
node_disk_writes_completed_total
node_disk_io_time_seconds_total
node_filesystem_size_bytes
node_filesystem_free_bytes
node_filesystem_avail_bytes
... (and 28 more)
```

#### 1.7 Infiniband/RDMA (25 metrics)

```
node_infiniband_port_data_received_bytes_total
node_infiniband_port_data_transmitted_bytes_total
node_infiniband_port_packets_received_total
node_infiniband_port_packets_transmitted_total
node_infiniband_rate_bytes_per_second
... (and 20 more)
```

#### 1.8 IPVS (8 metrics)

```
node_ipvs_connections_total
node_ipvs_incoming_bytes_total
node_ipvs_outgoing_bytes_total
node_ipvs_incoming_packets_total
node_ipvs_outgoing_packets_total
... (and 3 more)
```

#### 1.9 NFS (18 metrics)

```
node_nfs_connections_total
node_nfs_packets_total
node_nfs_requests_total
node_nfsd_server_rpcs_total
... (and 14 more)
```

#### 1.10 Load (3 metrics)

```
node_load1
node_load5
node_load15
```

---

### 2. Host Metrics (104)

#### 2.1 Network (29 metrics)

```
host_network_receive_bytes
host_network_receive_packets
host_network_receive_speed_bps
host_network_receive_speed_bitps
host_network_receive_dropped_packets
host_network_receive_errors
host_network_transmit_bytes
host_network_transmit_packets
host_network_transmit_speed_bps
host_network_transmit_speed_bitps
host_network_transmit_dropped_packets
host_network_transmit_errors
host_network_nic_bandwidth_usage_percent
host_network_ping_time_ns
host_network_ping_packet_loss_percent
host_network_loss_rate
host_network_rdma_receive_bytes
host_network_rdma_receive_packets
host_network_rdma_receive_speed_bitps
host_network_rdma_transmit_bytes
host_network_rdma_transmit_packets
host_network_rdma_transmit_speed_bitps
host_management_network_can_ping
host_storage_network_can_ping
host_to_zone_network_max_ping_time_ns_bucket
host_to_zone_network_max_ping_time_ns_count
host_to_zone_network_max_ping_time_ns_sum
... (and 2 more)
```

#### 2.2 CPU (9 metrics)

```
host_cpu_overall_usage_percent
host_cpu_overall_used_hz
host_cpu_overall_1m_avg_load
host_cpu_overall_5m_avg_load
host_cpu_overall_15m_avg_load
host_cpu_temperature_celsius
host_cpu_fan_speed_rpm
host_cpu_fan_is_ok
host_service_cpu_usage_percent
```

#### 2.3 Memory (16 metrics)

```
host_memory_usage_percent
host_memory_used_bytes
host_hp_memory_usage_percent
host_hp_memory_used_bytes
host_non_hp_memory_usage_percent
host_non_hp_memory_used_bytes
host_memory_swap_usage_percent
host_memory_swap_used_bytes
host_memory_swap_size_bytes
host_memory_swap_in_speed_bps
host_memory_swap_out_speed_bps
host_service_resident_memory_bytes
host_service_virtual_memory_bytes
host_service_shared_memory_bytes
host_all_service_resident_memory_bytes
host_other_service_resident_memory_bytes
```

#### 2.4 Disk/Storage (18 metrics)

```
host_disk_read_iops
host_disk_write_iops
host_disk_readwrite_iops
host_disk_read_speed_bps
host_disk_write_speed_bps
host_disk_readwrite_speed_bps
host_disk_avg_read_latency_ns
host_disk_avg_write_latency_ns
host_disk_avg_readwrite_latency_ns
host_disk_utilization_percent
host_disk_temperature_celsius
host_disk_remaining_life_percent
host_hdd_overall_size_bytes
host_ssd_overall_size_bytes
... (and 4 more)
```

#### 2.5 Other (32 metrics)

```
host_uptime_seconds
host_service_health
host_service_is_running
host_power_is_on
host_bond_slave_is_normal
host_ntp_server_numbers
host_can_connect_with_ntp_server
host_time_offset_with_ntp_leader_seconds
... (and 24 more)
```

---

### 3. ELF (VM) Metrics (69)

#### 3.1 Network (12 metrics)

```
elf_vm_network_receive_bytes
elf_vm_network_receive_packets
elf_vm_network_receive_speed_bps
elf_vm_network_receive_speed_bitps
elf_vm_network_receive_drop
elf_vm_network_receive_errors
elf_vm_network_transmit_bytes
elf_vm_network_transmit_packets
elf_vm_network_transmit_speed_bps
elf_vm_network_transmit_speed_bitps
elf_vm_network_transmit_drop
elf_vm_network_transmit_errors
```

#### 3.2 CPU (13 metrics)

```
elf_vm_cpu_overall_usage_percent
elf_vm_cpu_overall_used_hz
elf_vm_cpu_total_used_time
elf_vm_cpu_total_steal_time
elf_vm_cpu_overall_steal_time_percent
elf_vm_cpu_exclusive
elf_vm_cpu_qos_reservation_enabled
elf_host_vcpus_provisioned
elf_host_vcpus_provisioned_running
elf_host_vcpu_and_cpu_ratio
elf_cluster_vcpus_provisioned
elf_cluster_vcpus_provisioned_running
elf_cluster_cpu_model_compatibility
```

#### 3.3 Memory (8 metrics)

```
elf_vm_memory_usage_percent
elf_vm_memory_used_bytes
elf_vm_consumed_host_memory_bytes
elf_host_memory_provisioned_bytes
elf_host_memory_provisioned_running_bytes
elf_host_memory_ha_status
elf_cluster_memory_provisioned_bytes
elf_cluster_memory_provisioned_running_bytes
```

#### 3.4 Disk/Storage (28 metrics)

```
elf_vm_disk_read_iops
elf_vm_disk_write_iops
elf_vm_disk_readwrite_iops
elf_vm_disk_read_speed_bps
elf_vm_disk_write_speed_bps
elf_vm_disk_readwrite_speed_bps
elf_vm_disk_avg_read_latency_ns
elf_vm_disk_avg_write_latency_ns
elf_vm_disk_avg_readwrite_latency_ns
elf_vm_disk_logical_size_bytes
elf_vm_disk_iop30s
elf_vm_disk_overall_* (12 metrics - aggregated versions)
... (and more)
```

---

### 4. Container Metrics (128)

#### 4.1 Network (8 metrics)

```
container_network_receive_bytes_total
container_network_receive_packets_total
container_network_receive_packets_dropped_total
container_network_receive_errors_total
container_network_transmit_bytes_total
container_network_transmit_packets_total
container_network_transmit_packets_dropped_total
container_network_transmit_errors_total
```

#### 4.2 CPU (22 metrics)

```
container_cpu_usage_seconds_total
container_cpu_user_seconds_total
container_cpu_system_seconds_total
container_cpu_cfs_periods_total
container_cpu_cfs_throttled_periods_total
container_cpu_cfs_throttled_seconds_total
container_cpu_load_average_10s
... (and 15 more)
```

#### 4.3 Memory (65 metrics)

```
container_memory_usage_bytes
container_memory_working_set_bytes
container_memory_rss
container_memory_cache
container_memory_swap
container_memory_max_usage_bytes
container_memory_failcnt
container_memory_failures_total
... (and 57 more)
```

#### 4.4 Filesystem (17 metrics)

```
container_fs_usage_bytes
container_fs_limit_bytes
container_fs_reads_bytes_total
container_fs_writes_bytes_total
container_fs_reads_total
container_fs_writes_total
... (and 11 more)
```

---

### 5. ClickHouse Metrics (1835)

#### 5.1 Async Metrics (296)

Real-time system metrics collected asynchronously:

- Block I/O statistics per device
- CPU usage breakdowns
- Memory usage details
- Network I/O per interface

#### 5.2 Current Metrics (293)

Current state counters:

- Active connections
- Running queries
- Memory usage
- Thread pool states

#### 5.3 Profile Events (650)

Cumulative event counters:

- Query execution events
- I/O operations
- Network operations
- Cache hits/misses

#### 5.4 Error Metrics (596)

Error counters by type:

- Query errors
- Network errors
- Storage errors

---

### 6. ZBS Storage Metrics (966)

Distributed storage system metrics:

```
zbs_chunk_access_*          - Chunk access statistics
zbs_lsm_*                   - LSM tree metrics
zbs_meta_*                  - Metadata service
zbs_access_*                - Access layer
zbs_volume_*                - Volume statistics
zbs_replica_*               - Replication metrics
zbs_io_*                    - I/O statistics
```

---

### 7. Loki Metrics (226)

Log aggregation system:

#### 7.1 Ingester (70 metrics)

```
loki_ingester_streams_created_total
loki_ingester_chunks_flushed_total
loki_ingester_chunk_size_bytes
loki_ingester_memory_chunks
... (and 66 more)
```

#### 7.2 Chunk Store (36 metrics)

```
loki_chunk_store_chunks_per_query
loki_chunk_store_deduped_bytes_total
loki_chunk_fetcher_fetched_size_bytes
... (and 33 more)
```

#### 7.3 Distributor (4 metrics)

```
loki_distributor_bytes_received_total
loki_distributor_lines_received_total
loki_distributor_replication_factor
loki_distributor_structured_metadata_bytes_received_total
```

#### 7.4 Querier (14 metrics)

```
loki_querier_index_cache_hits_total
loki_querier_index_cache_gets_total
loki_querier_tail_active
... (and 11 more)
```

---

### 8. PostgreSQL Metrics (335)

#### 8.1 Database Statistics (43 metrics)

```
pg_stat_database_blks_read
pg_stat_database_blks_hit
pg_stat_database_tup_returned
pg_stat_database_tup_fetched
pg_stat_database_tup_inserted
pg_stat_database_tup_updated
pg_stat_database_tup_deleted
pg_stat_database_conflicts
pg_stat_database_deadlocks
... (and 34 more)
```

#### 8.2 Replication (12 metrics)

```
pg_replication_lag_seconds
pg_replication_is_replica
pg_replication_slot_*
pg_stat_replication_*
```

#### 8.3 Settings (244 metrics)

All PostgreSQL configuration parameters exposed as metrics.

---

### 9. VictoriaMetrics Self-Metrics (331)

#### 9.1 Data Ingestion

```
vm_rows_inserted_total
vm_rows_added_to_storage_total
vm_rows_ignored_total
vm_pending_rows
```

#### 9.2 Query Performance

```
vm_http_request_duration_seconds
vm_http_requests_total
vm_cache_hits_total
vm_cache_misses_total
```

#### 9.3 VMAgent (46 metrics)

```
vmagent_remotewrite_*       - Remote write metrics
vmagent_relabel_*           - Relabeling metrics
```

#### 9.4 VMAlert (50 metrics)

```
vmalert_alerts_fired_total
vmalert_alerts_firing
vmalert_alerts_pending
vmalert_recording_rules_*
```

---

### 10. Traefik Metrics (20)

```
traefik_entrypoint_requests_total
traefik_entrypoint_request_duration_seconds
traefik_entrypoint_requests_bytes_total
traefik_entrypoint_responses_bytes_total
traefik_entrypoint_open_connections
traefik_service_requests_total
traefik_service_request_duration_seconds
traefik_service_requests_bytes_total
traefik_service_responses_bytes_total
traefik_service_open_connections
traefik_config_reloads_total
traefik_config_reloads_failure_total
... (and 8 more)
```

---

### 11. Kubernetes Metrics (31)

```
kubelet_running_pods
kubelet_running_containers
kubelet_pod_start_duration_seconds
kubelet_runtime_operations_total
kubelet_runtime_operations_errors_total
kubelet_pleg_relist_duration_seconds
kubeproxy_sync_proxy_rules_duration_seconds
kubeproxy_network_programming_duration_seconds
kubernetes_build_info
... (and 22 more)
```

---

### 12. Go Runtime Metrics (127)

```
go_goroutines
go_threads
go_memstats_alloc_bytes
go_memstats_heap_alloc_bytes
go_gc_duration_seconds
go_cpu_classes_*
go_memory_classes_*
go_sched_*
```

---

### 13. Process Metrics (41)

```
process_cpu_seconds_total
process_resident_memory_bytes
process_virtual_memory_bytes
process_open_fds
process_max_fds
process_start_time_seconds
process_network_receive_bytes_total
process_network_transmit_bytes_total
... (and 33 more)
```

---

## Part 2: traffic-visualization-query-api Endpoints

**Backend URL**: http://queryloader:8011
**Data Source Type**: JSON API (marcusolsson-json-datasource)
**Total Endpoints**: 7

### API Endpoint Reference

#### 1. `/query/overview/overall_flow_count`

- **Method**: POST
- **Description**: Get total flow count
- **Response Fields**:| Field | JSONPath                        | Type   |
  | ----- | ------------------------------- | ------ |
  | value | `$.result.data.flow_count[0]` | number |

#### 2. `/query/overview/overall_flow_trend`

- **Method**: POST
- **Description**: Get flow count over time
- **Response Fields**:| Field      | JSONPath                       | Type   |
  | ---------- | ------------------------------ | ------ |
  | time       | `$.result.data.time.*`       | time   |
  | flow_count | `$.result.data.flow_count.*` | number |

#### 3. `/query/overview/overall_bandwidth_trend`

- **Method**: POST
- **Description**: Get bandwidth trend over time
- **Response Fields**:| Field                   | JSONPath                                | Type   |
  | ----------------------- | --------------------------------------- | ------ |
  | time                    | `$.result.data.time.*`                | time   |
  | send_bandwidth_total    | `$.result.data.out_bits_per_second.*` | number |
  | receive_bandwidth_total | `$.result.data.in_bits_per_second.*`  | number |

#### 4. `/query/overview/overall_flow_type`

- **Method**: POST
- **Description**: Get flow count by traffic type
- **Response Fields**:| Field        | JSONPath                         | Type   |
  | ------------ | -------------------------------- | ------ |
  | time         | `$.result.data.time.*`         | time   |
  | traffic_type | `$.result.data.traffic_type.*` | string |
  | value        | `$.result.data.flow_count.*`   | number |

#### 5. `/query/overview/top_n_flow_count_trend`

- **Method**: POST
- **Description**: Get top N entities by flow count
- **Response Fields**:| Field | JSONPath                       | Type   |
  | ----- | ------------------------------ | ------ |
  | name  | `$.result.data.name.*`       | string |
  | value | `$.result.data.flow_count.*` | number |
  | time  | `$.result.data.time.*`       | time   |

#### 6. `/query/overview/top_n_bandwidth_trend`

- **Method**: POST
- **Description**: Get top N entities by bandwidth
- **Response Fields**:| Field | JSONPath                            | Type   |
  | ----- | ----------------------------------- | ------ |
  | name  | `$.result.data.name.*`            | string |
  | value | `$.result.data.bits_per_second.*` | number |
  | time  | `$.result.data.time.*`            | time   |

#### 7. `/query/overview/top_n_rtt_avg_trend`

- **Method**: POST
- **Description**: Get top N entities by average RTT
- **Response Fields**:| Field | JSONPath                    | Type   |
  | ----- | --------------------------- | ------ |
  | name  | `$.result.data.name.*`    | string |
  | value | `$.result.data.rtt_avg.*` | number |
  | time  | `$.result.data.time.*`    | time   |

---

## Part 3: Related Dashboards

| Dashboard                            | UID                                  | Data Sources Used               |
| ------------------------------------ | ------------------------------------ | ------------------------------- |
| Traffic Visualization Overview en-US | traffic-visualization-overview-en-US | traffic-visualization-query-api |
| Traffic Visualization Overview zh-CN | traffic-visualization-overview-zh-CN | traffic-visualization-query-api |
| Traffic Visualization Panel Detail   | traffic-visualization-detail         | traffic-visualization-query-api |
| Network                              | AVGVYCaNk                            | VictoriaMetrics                 |
| Host & SCVM (node-exporter)          | rYdddlPWk2                           | VictoriaMetrics                 |
| VM                                   | HrUDWv-Nk                            | VictoriaMetrics                 |
| VM Resource                          | 1i2psM9Hk                            | VictoriaMetrics                 |
| ELF                                  | me7C2uaNz                            | VictoriaMetrics                 |
| Cluster                              | HJAchGaNk1                           | VictoriaMetrics                 |

---

## Appendix: Query Examples

### Prometheus/VictoriaMetrics Queries

```promql
# VM Network receive rate (bytes/s)
rate(elf_vm_network_receive_bytes[5m])

# Host network bandwidth usage
host_network_receive_speed_bitps + host_network_transmit_speed_bitps

# TCP retransmission rate
rate(node_netstat_Tcp_RetransSegs[5m]) / rate(node_netstat_Tcp_OutSegs[5m])

# Container network I/O
sum by (container_name) (rate(container_network_receive_bytes_total[5m]))

# Top 10 hosts by network traffic
topk(10, sum by (instance) (rate(node_network_receive_bytes_total[5m])))
```

### Grafana Explore Configuration for traffic-visualization-query-api

1. Select data source: `traffic-visualization-query-api`
2. Configure query:
   - **Method**: POST
   - **URL Path**: `/query/overview/overall_flow_trend`
   - **Body**: (depends on API requirements)
3. Configure fields using JSONPath expressions:
   - Time: `$.result.data.time.*`
   - Value: `$.result.data.flow_count.*`

---

## Part 4: Environment Analysis - Dogfood Cluster (192.168.18.52)

**Server**: http://192.168.18.52/grafana
**Cluster**: `Dogfood-SMTXOS-63x-17.99-MLAG`
**Analysis Period**: 24 hours (2025-12-08 to 2025-12-09)
**Data Resolution**: 30 seconds (minimum granularity, 2881 data points per node)
**Total Nodes**: 12

### 4.1 Cluster Node Inventory

| Hostname                         | Short Name       |
| -------------------------------- | ---------------- |
| dogfood-idc-elf-98               | 98               |
| dogfood-idc-elf-99               | 99               |
| dogfood-idc-elf-100              | 100              |
| dogfood-idc-elf-103              | 103              |
| dogfood-idc-elf-104              | 104              |
| dogfood-idc-elf-105-no-dual-life | 105-no-dual-life |
| dogfood-idc-elf-107              | 107              |
| dogfood-idc-elf-109-GPU-A16      | 109-GPU-A16      |
| dogfood-idc-elf-19-21-NVME-M2    | 19-21-NVME-M2    |
| dogfood-idc-elf-19-41-GPU-T4     | 19-41-GPU-T4     |
| dogfood-idc-elf-19-43            | 19-43            |
| dogfood-idc-elf-19-85            | 19-85            |

### 4.2 OVS CPU Utilization Distribution (24-hour)

**Metric**: `host_service_cpu_usage_percent{_service="ovs-vswitchd"}`
**Note**: Values are percentage relative to a single CPU core (can exceed 100%)

#### Percentile Comparison (30s step, 2881 data points per node)

| Node                        | P50             | P95             | P99             | Max             |
| --------------------------- | --------------- | --------------- | --------------- | --------------- |
| 98                          | 25.4%           | 43.0%           | 51.8%           | 67.0%           |
| 99                          | 18.0%           | 28.5%           | 34.0%           | 45.4%           |
| 100                         | 20.6%           | 33.1%           | 40.0%           | 54.3%           |
| 103                         | 26.5%           | 42.0%           | 48.0%           | 65.5%           |
| 104                         | 25.1%           | 41.0%           | 48.0%           | 62.0%           |
| 105-no-dual-life            | 20.7%           | 35.5%           | 42.9%           | 49.3%           |
| 107                         | 27.7%           | 43.3%           | 51.9%           | 59.0%           |
| 109-GPU-A16                 | 38.2%           | 58.4%           | 68.0%           | 83.3%           |
| 19-21-NVME-M2               | 26.0%           | 42.8%           | 52.6%           | 72.0%           |
| **19-41-GPU-T4**      | **50.1%** | **73.0%** | **83.0%** | **91.0%** |
| **19-43**             | **37.3%** | **57.3%** | **68.8%** | **75.9%** |
| **19-85**             | **42.3%** | **63.1%** | **71.8%** | **83.0%** |
| **Cluster Aggregate** | **28.0%** | **56.2%** | **70.0%** | **91.0%** |

### 4.3 Network Cgroup CPU Utilization Distribution (24-hour)

**Metric**: `(1 - cpu_cpuset_state_percent{_cpu="cpuset:/zbs/network", _state="idle"}) * 100`
**Note**: Network cgroup has 2 CPU cores allocated; percentage is relative to 2 cores

#### Percentile Comparison (30s step, 2881 data points per node)

| Node                        | P50             | P95             | P99             | Max             |
| --------------------------- | --------------- | --------------- | --------------- | --------------- |
| 98                          | 21.9%           | 27.7%           | 30.0%           | 32.6%           |
| 99                          | 20.6%           | 26.2%           | 27.9%           | 31.2%           |
| 100                         | 20.9%           | 26.7%           | 28.6%           | 30.2%           |
| 103                         | 24.5%           | 29.7%           | 31.5%           | 33.9%           |
| 104                         | 26.3%           | 30.9%           | 32.2%           | 33.6%           |
| 105-no-dual-life            | 24.6%           | 28.7%           | 29.7%           | 30.9%           |
| 107                         | 28.2%           | 34.0%           | 35.7%           | 38.8%           |
| 109-GPU-A16                 | 34.9%           | 39.1%           | 40.7%           | 43.1%           |
| 19-21-NVME-M2               | 27.8%           | 33.5%           | 35.9%           | 38.0%           |
| **19-41-GPU-T4**      | **44.6%** | **49.1%** | **50.8%** | **53.2%** |
| **19-43**             | **36.6%** | **41.5%** | **43.1%** | **45.2%** |
| **19-85**             | **38.4%** | **42.8%** | **44.4%** | **46.8%** |
| **Cluster Aggregate** | **27.3%** | **44.1%** | **47.9%** | **53.2%** |

### 4.4 Host NIC Drop Statistics (24-hour)

**Metrics**: `node_network_receive_drop_total`, `node_network_transmit_drop_total`
**Devices**: Physical NICs only (eno*, bond*, eth*)

| Node                  | Device      | RX Drops (24h) | TX Drops (24h) |
| --------------------- | ----------- | -------------- | -------------- |
| dogfood-idc-elf-19-85 | eno3        | 25,630         | 0              |
| All other nodes       | All devices | 0              | 0              |

**Note**: Only `dogfood-idc-elf-19-85` showed RX packet drops on interface `eno3` during the 24-hour analysis period.

### 4.5 Key Findings

1. **High OVS CPU Nodes** (P95 > 55%):

   - `19-41-GPU-T4`: P50=50.1%, P95=73.0%, Max=91.0% ⚠️ **Highest**
   - `19-85`: P50=42.3%, P95=63.1%, Max=83.0%
   - `109-GPU-A16`: P50=38.2%, P95=58.4%, Max=83.3%
   - `19-43`: P50=37.3%, P95=57.3%, Max=75.9%
2. **High Network Cgroup Nodes** (P95 > 40%):

   - `19-41-GPU-T4`: P50=44.6%, P95=49.1%, Max=53.2% ⚠️ **Exceeds 50% (saturation warning)**
   - `19-85`: P50=38.4%, P95=42.8%, Max=46.8%
   - `19-43`: P50=36.6%, P95=41.5%, Max=45.2%
   - `109-GPU-A16`: P50=34.9%, P95=39.1%, Max=43.1%
3. **Packet Drops**:

   - Only `19-85` shows RX drops (25,630 packets on eno3)
   - No TX drops observed on any node
4. **GPU/Special Nodes Pattern**:

   - GPU nodes (T4, A16) and `19-43` show higher OVS CPU utilization
   - This correlates with higher VM network activity on GPU workloads
   - `19-41-GPU-T4` is the most critical node requiring attention

### 4.6 Recommendations

1. **Critical - 19-41-GPU-T4**:

   - OVS CPU P50=50.1% (already at median above 50%)
   - Network cgroup Max=53.2% (exceeds 2-core allocation)
   - Consider OVS flow table optimization or additional CPU allocation
2. **High Priority - 19-43, 19-85**:

   - Both show elevated OVS/network CPU usage
   - `19-85` has RX drops (25,630 packets on eno3) - check NIC ring buffer (`ethtool -g/-G`)
3. **Monitor - 109-GPU-A16**:

   - P95 OVS CPU at 58.4%, trending toward saturation
4. **Network cgroup allocation**:

   - Consider increasing CPU allocation for high-traffic nodes (19-41-GPU-T4, 19-43, 19-85)

---

*Report generated: 2025-12-04*
*Last updated: 2025-12-09 (added Part 4: Dogfood Cluster Analysis)*
