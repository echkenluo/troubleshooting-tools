# Commonly Used Grafana Metrics - Label Reference

**Server**: http://192.168.79.79/grafana
**Data Source**: VictoriaMetrics (Prometheus-compatible)
**Generated**: 2025-12-04

This document contains label information for the most commonly used metrics in daily operations and troubleshooting.

---

## Table of Contents

1. [CPU and Service Metrics](#1-cpu-and-service-metrics)
   - [cpu_cpuset_state_percent](#11-cpu_cpuset_state_percent)
   - [host_service_cpu_usage_percent](#12-host_service_cpu_usage_percent)
2. [OVS Coverage Metrics](#2-ovs-coverage-metrics)
3. [Host Network Metrics](#3-host-network-metrics)
   - [node_network_* (Node Exporter)](#31-node_network-node-exporter)
   - [host_network_* (Custom Host Metrics)](#32-host_network-custom-host-metrics)
4. [Loki Metrics](#4-loki-metrics)

---

## 1. CPU and Service Metrics

### 1.1 cpu_cpuset_state_percent

CPU usage percentage by cgroup/cpuset. Used for monitoring ZBS storage system CPU isolation.

**Available Labels**:

| Label             | Description              |
| ----------------- | ------------------------ |
| `_cluster_uuid` | Cluster identifier       |
| `_cpu`          | CPU set name (cgroup)    |
| `hostname`      | Host name                |
| `instance`      | Prometheus scrape target |
| `job`           | Prometheus job name      |

**Available `_cpu` (cpuset) Values** (7 total):

| Cpuset                 | Description                            |
| ---------------------- | -------------------------------------- |
| `cpuset-access`      | ZBS Access layer CPU allocation        |
| `cpuset-chunk`       | ZBS Chunk service CPU allocation       |
| `cpuset-meta`        | ZBS Meta service CPU allocation        |
| `cpuset-others`      | Other processes CPU allocation         |
| `cpuset-recover`     | ZBS Recovery process CPU allocation    |
| `cpuset-replication` | ZBS Replication process CPU allocation |
| `cpuset-system`      | System processes CPU allocation        |

**Example Queries**:

```promql
# CPU usage by cpuset across all hosts
cpu_cpuset_state_percent{_cpu="cpuset-chunk"}

# CPU usage for specific host and cpuset
cpu_cpuset_state_percent{hostname="zbs-node-01", _cpu="cpuset-access"}

# Average CPU usage by cpuset type
avg by (_cpu) (cpu_cpuset_state_percent)
```

---

### 1.2 host_service_cpu_usage_percent

CPU usage percentage by system service. Used for monitoring individual service resource consumption.

**Available Labels**:

| Label             | Description              |
| ----------------- | ------------------------ |
| `_cluster_uuid` | Cluster identifier       |
| `_service`      | Service name             |
| `hostname`      | Host name                |
| `instance`      | Prometheus scrape target |
| `job`           | Prometheus job name      |

**Available `_service` Values** (71 total):

#### Storage Services (ZBS)

| Service                    | Description                 |
| -------------------------- | --------------------------- |
| `zbs_access_svc`         | ZBS Access service          |
| `zbs_chunk_svc`          | ZBS Chunk storage service   |
| `zbs_meta_svc`           | ZBS Metadata service        |
| `zbs_meta_master_svc`    | ZBS Meta master service     |
| `zbs_meta_upgrade_svc`   | ZBS Meta upgrade service    |
| `zbs_recover_svc`        | ZBS Recovery service        |
| `zbs_replication_svc`    | ZBS Replication service     |
| `zbs_rest_svc`           | ZBS REST API service        |
| `zbs_deploy_tool_svc`    | ZBS Deployment tool service |
| `zbs_log_tool_svc`       | ZBS Log collection tool     |
| `zbs_client_manager_svc` | ZBS Client manager          |
| `zbs_taskflow_svc`       | ZBS Task workflow service   |
| `zbs_scvm_svc`           | ZBS SCVM service            |

#### Virtualization Services

| Service                  | Description                 |
| ------------------------ | --------------------------- |
| `libvirtd_svc`         | Libvirt daemon              |
| `qemu_svc`             | QEMU emulator               |
| `cloudtower_agent_svc` | CloudTower management agent |
| `elf_vhost_user_svc`   | ELF vhost-user service      |
| `elf_vm_svc`           | ELF VM service              |
| `ovs_vswitchd_svc`     | Open vSwitch daemon         |
| `ovsdb_server_svc`     | OVS database server         |

#### System Services

| Service                  | Description              |
| ------------------------ | ------------------------ |
| `chronyd_svc`          | Chrony NTP daemon        |
| `containerd_svc`       | Container runtime        |
| `crond_svc`            | Cron daemon              |
| `dbus_daemon_svc`      | D-Bus message bus        |
| `gssproxy_svc`         | GSSAPI proxy daemon      |
| `irqbalance_svc`       | IRQ balancing daemon     |
| `polkitd_svc`          | PolicyKit daemon         |
| `rpcbind_svc`          | RPC bind service         |
| `rsyslogd_svc`         | System logging service   |
| `sshd_svc`             | SSH daemon               |
| `sssd_svc`             | System Security Services |
| `systemd_journald_svc` | Journal logging service  |
| `systemd_logind_svc`   | Login manager            |
| `systemd_udevd_svc`    | udev device manager      |
| `tuned_svc`            | Tuned system tuning      |

#### Network Services

| Service                | Description           |
| ---------------------- | --------------------- |
| `NetworkManager_svc` | NetworkManager        |
| `dnsmasq_svc`        | DNS/DHCP server       |
| `haproxy_svc`        | HAProxy load balancer |
| `keepalived_svc`     | Keepalived VRRP       |

#### Monitoring Services

| Service               | Description                |
| --------------------- | -------------------------- |
| `cadvisor_svc`      | cAdvisor container metrics |
| `node_exporter_svc` | Node Exporter              |
| `promtail_svc`      | Promtail log shipper       |
| `vmagent_svc`       | VictoriaMetrics agent      |
| `vmsingle_svc`      | VictoriaMetrics single     |

#### SMTX/CloudTower Services

| Service                         | Description             |
| ------------------------------- | ----------------------- |
| `smtx_backend_svc`            | SMTX backend            |
| `smtx_cloudfs_svc`            | SMTX CloudFS            |
| `smtx_component_toolkit_svc`  | SMTX component toolkit  |
| `smtx_crs_svc`                | SMTX CRS service        |
| `smtx_datacenter_svc`         | SMTX datacenter         |
| `smtx_deploy_server_svc`      | SMTX deploy server      |
| `smtx_dpu_toolkit_svc`        | SMTX DPU toolkit        |
| `smtx_monitor_center_svc`     | SMTX monitor center     |
| `smtx_prepare_server_svc`     | SMTX prepare server     |
| `smtx_process_toolkit_svc`    | SMTX process toolkit    |
| `smtx_register_svc`           | SMTX register           |
| `smtx_replication_center_svc` | SMTX replication center |
| `smtx_replication_master_svc` | SMTX replication master |
| `smtx_upgrade_svc`            | SMTX upgrade service    |
| `smtx_upgradecenter_svc`      | SMTX upgrade center     |
| `smtx_usb_server_svc`         | SMTX USB server         |
| `smtx_usb_toolkit_svc`        | SMTX USB toolkit        |

#### Kubernetes/Container Services

| Service                         | Description               |
| ------------------------------- | ------------------------- |
| `etcd_svc`                    | etcd distributed KV store |
| `kube_apiserver_svc`          | Kubernetes API server     |
| `kube_controller_manager_svc` | K8s controller manager    |
| `kube_proxy_svc`              | Kubernetes proxy          |
| `kube_scheduler_svc`          | Kubernetes scheduler      |
| `kubelet_svc`                 | Kubelet node agent        |

#### Other Services

| Service                   | Description          |
| ------------------------- | -------------------- |
| `elf_agent_svc`         | ELF agent            |
| `multipath_manager_svc` | Multipath manager    |
| `spice_vdagentd_svc`    | SPICE VDAgent daemon |

**Example Queries**:

```promql
# CPU usage for ZBS chunk service
host_service_cpu_usage_percent{_service="zbs_chunk_svc"}

# Top 10 services by CPU usage
topk(10, host_service_cpu_usage_percent)

# All ZBS services CPU usage
host_service_cpu_usage_percent{_service=~"zbs_.*"}

# OVS services CPU usage
host_service_cpu_usage_percent{_service=~"ovs.*"}
```

---

## 2. OVS Coverage Metrics

Open vSwitch coverage counter metrics for monitoring OVS internal statistics.

**Available Metrics** (9 total):

| Metric                                               | Description                    |
| ---------------------------------------------------- | ------------------------------ |
| `openvswitch_coverage_ovs_async_counter`           | Asynchronous operation counter |
| `openvswitch_coverage_ovs_current_counter`         | Current operations counter     |
| `openvswitch_coverage_ovs_histogram_count_counter` | Histogram count                |
| `openvswitch_coverage_ovs_histogram_sum_counter`   | Histogram sum                  |
| `openvswitch_coverage_ovs_iterator_bool_counter`   | Iterator boolean counter       |
| `openvswitch_coverage_ovs_iterator_counter`        | Iterator counter               |
| `openvswitch_coverage_ovs_scalar_counter`          | Scalar counter                 |
| `openvswitch_coverage_ovs_threshold_counter`       | Threshold counter              |
| `openvswitch_coverage_ovs_vlog_counter`            | Vlog message counter           |

**Available Labels**:

| Label             | Description              |
| ----------------- | ------------------------ |
| `_cluster_uuid` | Cluster identifier       |
| `hostname`      | Host name                |
| `instance`      | Prometheus scrape target |
| `job`           | Prometheus job name      |
| `mode`          | Counter mode/type        |

**Example Queries**:

```promql
# All OVS coverage counters for a host
openvswitch_coverage_ovs_async_counter{hostname="node-01"}

# Rate of async operations
rate(openvswitch_coverage_ovs_async_counter[5m])

# OVS vlog message rate (useful for detecting issues)
rate(openvswitch_coverage_ovs_vlog_counter[5m])
```

---

## 3. Host Network Metrics

### 3.1 node_network_* (Node Exporter)

Standard Linux network interface metrics from node_exporter.

**Available Metrics** (36 total):

| Category           | Metrics                                                                                                                                                                                                                                                                                                                                                          |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Receive**  | `node_network_receive_bytes_total`, `node_network_receive_packets_total`, `node_network_receive_errs_total`, `node_network_receive_drop_total`, `node_network_receive_fifo_total`, `node_network_receive_frame_total`, `node_network_receive_compressed_total`, `node_network_receive_multicast_total`, `node_network_receive_nohandler_total` |
| **Transmit** | `node_network_transmit_bytes_total`, `node_network_transmit_packets_total`, `node_network_transmit_errs_total`, `node_network_transmit_drop_total`, `node_network_transmit_fifo_total`, `node_network_transmit_colls_total`, `node_network_transmit_carrier_total`, `node_network_transmit_compressed_total`                                     |
| **Status**   | `node_network_up`, `node_network_carrier`, `node_network_carrier_changes_total`, `node_network_carrier_up_changes_total`, `node_network_carrier_down_changes_total`                                                                                                                                                                                    |
| **Info**     | `node_network_info`, `node_network_address_assign_type`, `node_network_flags`, `node_network_iface_id`, `node_network_iface_link`, `node_network_iface_link_mode`                                                                                                                                                                                    |
| **Physical** | `node_network_speed_bytes`, `node_network_mtu_bytes`, `node_network_transmit_queue_length`, `node_network_dormant`, `node_network_device_id`, `node_network_net_dev_group`, `node_network_protocol_type`                                                                                                                                           |

**Available Labels**:

| Label        | Description              |
| ------------ | ------------------------ |
| `device`   | Network interface name   |
| `instance` | Prometheus scrape target |
| `job`      | Prometheus job name      |

**Available `device` Values** (278 total):

#### Physical NICs

| Device Pattern                         | Description            |
| -------------------------------------- | ---------------------- |
| `eno1`, `eno2`, `eno3`, `eno4` | Onboard Ethernet ports |
| `enp*`                               | PCIe network adapters  |
| `bond0`                              | Bonded interface       |

#### Virtual Interfaces

| Device Pattern | Description                          |
| -------------- | ------------------------------------ |
| `vnet*`      | Virtual network interfaces (VM NICs) |
| `ovsbr-*`    | OVS bridge interfaces                |
| `port-*`     | OVS port interfaces                  |
| `virbr*`     | Libvirt bridge interfaces            |

#### System Interfaces

| Device Pattern | Description                 |
| -------------- | --------------------------- |
| `lo`         | Loopback interface          |
| `docker0`    | Docker bridge               |
| `veth*`      | Virtual Ethernet pairs      |
| `flannel.*`  | Flannel overlay network     |
| `cni*`       | Container Network Interface |

**Sample Device List** (first 50):

```
bond0, cni0, docker0, eno1, eno2, eno3, eno4, enp1s0f0, enp1s0f1,
enp1s0np0, enp5s0f0, enp5s0f1, eth0, flannel.1, lo, ovn-k8s-mp0,
ovsbr-access, ovsbr-internal, ovsbr-san, ovsbr-storage, ovsbr-wan,
port-access-vlan, port-internal-vlan, port-san-vlan, port-storage-vlan,
veth0, veth1, virbr0, vnet0, vnet1, vnet2, vnet3, vnet4, vnet5...
```

**Example Queries**:

```promql
# Physical NIC receive rate
rate(node_network_receive_bytes_total{device=~"eno[1-4]|bond0"}[5m])

# VM interface traffic
rate(node_network_transmit_bytes_total{device=~"vnet.*"}[5m])

# OVS bridge traffic
rate(node_network_receive_bytes_total{device=~"ovsbr-.*"}[5m])

# Interface errors
rate(node_network_receive_errs_total[5m]) + rate(node_network_transmit_errs_total[5m])

# Packet drops by interface
rate(node_network_receive_drop_total[5m]) + rate(node_network_transmit_drop_total[5m])
```

---

### 3.2 host_network_* (Custom Host Metrics)

Custom host-level network metrics with cluster awareness.

**Available Metrics** (24 total):

| Category           | Metrics                                                                                                                                                                                                                                         |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Receive**  | `host_network_receive_bytes`, `host_network_receive_packets`, `host_network_receive_speed_bps`, `host_network_receive_speed_bitps`, `host_network_receive_dropped_packets`, `host_network_receive_errors`                           |
| **Transmit** | `host_network_transmit_bytes`, `host_network_transmit_packets`, `host_network_transmit_speed_bps`, `host_network_transmit_speed_bitps`, `host_network_transmit_dropped_packets`, `host_network_transmit_errors`                     |
| **RDMA**     | `host_network_rdma_receive_bytes`, `host_network_rdma_receive_packets`, `host_network_rdma_receive_speed_bitps`, `host_network_rdma_transmit_bytes`, `host_network_rdma_transmit_packets`, `host_network_rdma_transmit_speed_bitps` |
| **Status**   | `host_network_nic_bandwidth_usage_percent`, `host_network_loss_rate`                                                                                                                                                                        |
| **Ping**     | `host_network_ping_time_ns`, `host_network_ping_packet_loss_percent`, `host_management_network_can_ping`, `host_storage_network_can_ping`                                                                                               |

**Available Labels**:

| Label             | Description              |
| ----------------- | ------------------------ |
| `_cluster_uuid` | Cluster identifier       |
| `_device`       | Network device name      |
| `hostname`      | Host name                |
| `instance`      | Prometheus scrape target |
| `job`           | Prometheus job name      |

**Available `hostname` Values** (6 hosts in sample cluster):

```
zbs-node-01
zbs-node-02
zbs-node-03
zbs-node-04
zbs-node-05
zbs-node-06
```

**Example Queries**:

```promql
# Network receive speed by host
host_network_receive_speed_bitps{hostname=~"zbs-node-.*"}

# NIC bandwidth utilization
host_network_nic_bandwidth_usage_percent > 80

# RDMA traffic monitoring
host_network_rdma_receive_speed_bitps + host_network_rdma_transmit_speed_bitps

# Ping latency between hosts
host_network_ping_time_ns / 1e6  # Convert to ms

# Network loss rate alert
host_network_loss_rate > 0.01
```

---

## 4. Loki Metrics

Log aggregation system internal metrics for monitoring Loki health and performance.

**Total Metrics**: 226

### Metrics by Component

#### Ingester (70 metrics)

Primary component for log ingestion and storage.

| Subcategory       | Key Metrics                                                                                                                                                                                                                                                                                                                                                      |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Streams** | `loki_ingester_streams_created_total`, `loki_ingester_streams_removed_total`, `loki_ingester_memory_streams`                                                                                                                                                                                                                                               |
| **Chunks**  | `loki_ingester_chunks_created_total`, `loki_ingester_chunks_flushed_total`, `loki_ingester_chunks_stored_total`, `loki_ingester_chunk_size_bytes`, `loki_ingester_chunk_entries`, `loki_ingester_chunk_utilization`, `loki_ingester_chunk_age_seconds`, `loki_ingester_chunk_encode_time_seconds`, `loki_ingester_chunk_compress_time_seconds` |
| **Memory**  | `loki_ingester_memory_chunks`, `loki_ingester_memory_chunks_flushed`                                                                                                                                                                                                                                                                                         |
| **WAL**     | `loki_ingester_wal_bytes_in_use`, `loki_ingester_wal_disk_full_failures_total`, `loki_ingester_wal_logged_bytes_total`, `loki_ingester_wal_records_logged_total`, `loki_ingester_wal_replay_duration_seconds`, `loki_ingester_wal_replay_flushing`                                                                                                   |
| **Flush**   | `loki_ingester_flush_queue_length`, `loki_ingester_flush_size_bytes`                                                                                                                                                                                                                                                                                         |

#### Chunk Store (36 metrics)

Storage backend for chunks.

| Key Metrics                                                                                                                                                                |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `loki_chunk_store_chunks_per_query`, `loki_chunk_store_deduped_bytes_total`, `loki_chunk_store_deduped_chunks_total`, `loki_chunk_store_index_entries_per_chunk`   |
| `loki_chunk_fetcher_fetched_chunks_total`, `loki_chunk_fetcher_fetched_size_bytes`, `loki_chunk_fetcher_cache_hits_total`, `loki_chunk_fetcher_cache_misses_total` |

#### Distributor (4 metrics)

Handles incoming log streams and distributes to ingesters.

| Metric                                                        | Description               |
| ------------------------------------------------------------- | ------------------------- |
| `loki_distributor_bytes_received_total`                     | Total bytes received      |
| `loki_distributor_lines_received_total`                     | Total log lines received  |
| `loki_distributor_replication_factor`                       | Replication factor        |
| `loki_distributor_structured_metadata_bytes_received_total` | Structured metadata bytes |

#### Querier (14 metrics)

Query processing component.

| Key Metrics                                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------- |
| `loki_querier_index_cache_hits_total`, `loki_querier_index_cache_gets_total`, `loki_querier_index_cache_puts_total` |
| `loki_querier_tail_active`, `loki_querier_tail_deleted_streams_total`                                                 |

#### Compactor (20 metrics)

Background compaction and retention processing.

| Key Metrics                                                              |
| ------------------------------------------------------------------------ |
| `loki_compactor_apply_retention_last_successful_run_timestamp_seconds` |
| `loki_compactor_apply_retention_operation_duration_seconds`            |
| `loki_compactor_apply_retention_operation_total`                       |
| `loki_compactor_delete_requests_processed_total`                       |
| `loki_compactor_running`                                               |

#### Cache (18 metrics)

Caching layer metrics.

| Key Metrics                                                                                             |
| ------------------------------------------------------------------------------------------------------- |
| `loki_cache_fetched_keys`, `loki_cache_hits`, `loki_cache_request_duration_seconds`               |
| `loki_embeddedcache_added_total`, `loki_embeddedcache_entries`, `loki_embeddedcache_memory_bytes` |

#### BoltDB/Index (24 metrics)

Index storage metrics.

| Key Metrics                                                        |
| ------------------------------------------------------------------ |
| `loki_boltdb_shipper_compact_tables_operation_duration_seconds`  |
| `loki_boltdb_shipper_compacted_index_operation_duration_seconds` |
| `loki_boltdb_shipper_downloaded_files_total`                     |
| `loki_boltdb_shipper_request_duration_seconds`                   |
| `loki_index_request_duration_seconds`                            |

#### Request/HTTP (12 metrics)

HTTP request handling metrics.

| Key Metrics                                                                                                              |
| ------------------------------------------------------------------------------------------------------------------------ |
| `loki_request_duration_seconds_bucket`, `loki_request_duration_seconds_count`, `loki_request_duration_seconds_sum` |

#### Ring (10 metrics)

Distributed hash ring for service discovery.

| Key Metrics                                                                                          |
| ---------------------------------------------------------------------------------------------------- |
| `loki_ring_member_heartbeats_total`, `loki_ring_member_ownership_percent`, `loki_ring_members` |

#### Other Components (18 metrics)

| Component           | Metrics                                                    |
| ------------------- | ---------------------------------------------------------- |
| **Ruler**     | `loki_ruler_*` - Rule evaluation metrics                 |
| **Scheduler** | `loki_scheduler_*` - Query scheduling                    |
| **Internal**  | `loki_internal_log_messages_total`, `loki_panic_total` |

**Example Queries**:

```promql
# Ingestion rate (lines/second)
rate(loki_distributor_lines_received_total[5m])

# Ingestion throughput (bytes/second)
rate(loki_distributor_bytes_received_total[5m])

# Active streams in ingesters
sum(loki_ingester_memory_streams)

# Chunk flush rate
rate(loki_ingester_chunks_flushed_total[5m])

# Query cache hit ratio
rate(loki_querier_index_cache_hits_total[5m]) / rate(loki_querier_index_cache_gets_total[5m])

# WAL disk usage
loki_ingester_wal_bytes_in_use

# Chunk store deduplication ratio
rate(loki_chunk_store_deduped_chunks_total[5m]) / rate(loki_chunk_store_chunks_per_query[5m])
```

---

## Appendix: Label Query API

To query available label values for any metric, use the Prometheus/VictoriaMetrics API:

```bash
# Get all values for a specific label
curl -s "http://192.168.79.79/grafana/api/datasources/proxy/1/api/v1/label/{label_name}/values?match[]={metric_name}"

# Example: Get all _service values
curl -s "http://192.168.79.79/grafana/api/datasources/proxy/1/api/v1/label/_service/values?match[]=host_service_cpu_usage_percent"

# Example: Get all device values for node_network metrics
curl -s "http://192.168.79.79/grafana/api/datasources/proxy/1/api/v1/label/device/values?match[]=node_network_receive_bytes_total"
```

**Authentication Required**:

- Traefik Basic Auth: `o11y:HC!r0cks`
- Grafana Session: `admin:HC!r0cks`

---

## Related Documents

- [Grafana Metrics Report](./grafana_metrics_report.md) - Summary report with all categories
- [Grafana Metrics Inventory](./grafana_metrics_inventory.md) - Complete metrics listing (5,641 metrics)

---

*Generated: 2025-12-04*
