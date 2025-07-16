# 系统网络概要

系统网络本身使用 ovs 上创建的 internal port 绑定一个 ip 地址，即系统网络地址。系统网络间通信的数据路径为：
协议栈 <-> ovs internal port <-> ovs kernel module <-> ovs userspace(optional, 仅部分数据包) <-> 物理网卡（ovs 上绑定的 uplink 物理口，可能是 1 ～n ， 因为支持 bond）。 
具体 ovs 相关 probe 点，见 bpftools/icmp_rtt_latency.py 中的实现，这个为针对 icmp 流量的双向延迟测量工具。

# 实现细节
1. TCP 连接识别
使用四元组（源IP、目标IP、源端口、目标端口）来唯一标识 TCP 连接
支持按 IP 和端口进行过滤

2. 单向延迟测量

TX 方向：从 tcp_sendmsg 开始，到 dev_queue_xmit 结束
RX 方向：从 __netif_receive_skb 开始，到 tcp_v4_rcv 结束
每个方向都是将整个数据路径氛围若干段，测量每一段的分段延迟，以及端到端的总延迟。

3. 阶段划分
程序追踪以下 7 个阶段：

Stage 0: TCP 初始化（TX: tcp_sendmsg, RX: __netif_receive_skb）
Stage 1: Internal device 处理（internal_dev_xmit/netdev_frame_hook）
Stage 2: OVS datapath 处理（ovs_dp_process_packet）
Stage 3: OVS upcall（ovs_dp_upcall）
Stage 4: OVS key 提取（ovs_flow_key_extract_userspace）
Stage 5: OVS vport 发送（ovs_vport_send）
Stage 6: 物理设备（TX: dev_queue_xmit, RX: tcp_v4_rcv）

4. TCP 特定信息

显示 TCP 序列号和确认号
显示 TCP 标志位（SYN, ACK, FIN, RST, PSH, URG）
显示负载长度

5. 使用示例
# 追踪从本地 192.168.1.10:8080 到 192.168.1.20:80 的出站 TCP 流量
sudo ./tcp_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                      --src-port 8080 --dst-port 80 \
                      --phy-iface1 eth0 --phy-iface2 eth1 --direction tx

# 追踪到本地 192.168.1.10 的入站 TCP 流量
sudo ./tcp_latency.py --src-ip 192.168.1.20 --dst-ip 192.168.1.10 \
                      --phy-iface1 eth0 --phy-iface2 eth1 --direction rx

# 追踪所有 TCP 流量（不限制 IP 和端口）
sudo ./tcp_latency.py --src-ip 0.0.0.0 --dst-ip 0.0.0.0 \
                      --phy-iface1 eth0 --direction tx

6. 与 ICMP 版本的主要区别

连接识别方式：TCP 使用四元组，而 ICMP 使用 ID 和序列号
探测点不同：

TCP TX 使用 tcp_sendmsg 作为起点
TCP RX 使用 tcp_v4_rcv 作为终点

单向测量：只测量一个方向的延迟，而不是往返时间
TCP 特定信息：显示 TCP 序列号、标志位等信息

7. 输出格式示例

=== TCP Latency Trace: 2025-01-15 10:30:45.123 (TX) ===
Connection: 192.168.1.10:8080 -> 192.168.1.20:80
TCP Info: SEQ=1234567 ACK=7654321 FLAGS=PA PAYLOAD=1024 bytes
Process: PID=1234 COMM=curl IF=eth0

Latencies (us):
  [0->1] S0_TCP_SENDMSG -> S1_INTERNAL_DEV: 12.345 us
  [1->2] S1_INTERNAL_DEV -> S2_OVS_DP_PROC: 8.234 us
  [2->5] S2_OVS_DP_PROC -> S5_OVS_VPORT_SND: 15.678 us (OVS No Upcall)
  [5->6] S5_OVS_VPORT_SND -> S6_DEV_QUEUE_XMIT: 5.123 us

Total Latency: 41.380 us


# 注意事项

skb 解析需要考虑是否有 vlan 的情况，分别解析



