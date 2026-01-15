# TCP/UDP Drop Detector Design Plan

## Confirmed Design Choices

Based on user requirements:
1. **Segmentation**: Pre-GSO tracking (at dev_queue_xmit entry, before hardware splits)
2. **UDP Fragments**: Fragment group tracking (first fragment starts group, subsequent extend it)
3. **TCP Mode**: Bidirectional tracking (like ICMP - track request/response pairs)

---

## Implementation Design

### Overview

Create two new tools following the `icmp_drop_detector.py` pattern:
1. `tcp_drop_detector.py` - Bidirectional TCP drop detection with seq-based tracking
2. `udp_drop_detector.py` - Fragment-group based UDP drop detection

### File Location

```
measurement-tools/linux-network-stack/packet-drop/
├── icmp_drop_detector.py  (existing)
├── tcp_drop_detector.py   (new)
└── udp_drop_detector.py   (new)
```

### Naming Convention

This project uses **Python snake_case** naming convention for eBPF/BCC tools:
- File names: `tcp_drop_detector.py`, `udp_drop_detector.py`
- Function names: `parse_tcp_packet()`, `get_if_index()`
- Variable names: `src_ip_hex`, `rx_ifaces`

This follows the Python community standard and is consistent with existing BCC tools in the repository. The project coding guidelines in `claude_local_coding.md` define these conventions.

---

## TCP Drop Detector Design

### Flow Key Structure

```c
struct tcp_flow_key {
    __be32 sip;           // Source IP (canonical: always SRC_IP_FILTER)
    __be32 dip;           // Destination IP (canonical: always DST_IP_FILTER)
    __be16 sport;         // Source port
    __be16 dport;         // Destination port
    __be32 seq;           // TCP sequence number
    __be16 payload_len;   // Payload length (distinguishes segments)
};
```

### 4-Stage Tracking (Like ICMP)

```
Request Direction (src→dst):
  [0] ReqRX: Request received at rx-iface (netif_receive_skb)
  [1] ReqTX: Request sent from tx-iface (dev_queue_xmit)

Response Direction (dst→src):
  [2] RepRX: Response received at tx-iface (netif_receive_skb)
  [3] RepTX: Response sent from rx-iface (dev_queue_xmit)
```

### TCP-Specific Considerations

1. **Direction Detection**:
   - Request: `(sip == SRC_IP, dip == DST_IP)` with SYN or data
   - Response: `(sip == DST_IP, dip == SRC_IP)` with ACK or data

2. **Canonical Key**: Always store with `(SRC_IP_FILTER, DST_IP_FILTER)` order
   - For responses, swap ports to match request's canonical form

3. **Packet Identification Strategy**:
   TCP packets are uniquely identified using a 6-tuple key:
   `{src_ip, dst_ip, src_port, dst_port, tcp_seq, payload_len}`

   This seq-based approach provides precise packet tracking:
   - Each TCP segment has a unique sequence number
   - Payload length distinguishes segments with same seq (e.g., retransmits)
   - No time window ambiguity - exact packet matching

   Note: Request/response are tracked independently by their own seq numbers,
   not by ACK matching. This simplifies implementation while maintaining accuracy.

### BPF Probes

```
netif_receive_skb tracepoint → Stage 0 (ReqRX) or Stage 2 (RepRX)
dev_queue_xmit kprobe        → Stage 1 (ReqTX) or Stage 3 (RepTX)
```

### Drop Detection Logic

| Has Stage | Missing Stage | Drop Type |
|-----------|---------------|-----------|
| ReqRX (0) | ReqTX (1) | Request dropped internally |
| ReqTX (1) | RepRX (2) | External drop (network/peer) |
| RepRX (2) | RepTX (3) | Response dropped internally |

---

## UDP Drop Detector Design

### Fragment Group Tracking

**Key Insight**: Track by IP ID, which remains constant across all fragments of same datagram.

### Flow Key Structure (Group Key)

```c
// Primary key includes ports to reduce IP ID collision risk
struct udp_group_key {
    __be32 sip;           // Source IP
    __be32 dip;           // Destination IP
    __be16 ip_id;         // IP identification (links all fragments)
    __be16 sport;         // Source port (0 if unknown)
    __be16 dport;         // Destination port (0 if unknown)
    __be16 pad;
};

// Secondary key for port lookup (used by non-first fragments)
struct udp_port_lookup_key {
    __be32 sip;
    __be32 dip;
    __be16 ip_id;
    __be16 pad;
};
```

**IP ID Collision Mitigation**: Including ports in the primary key reduces collision risk when IP ID wraps. A secondary port lookup map stores ports from first fragments, allowing non-first fragments to recover port information and use the full key.

### Fragment Group Data

```c
struct udp_group_data {
    u64 first_seen_ns;
    u64 ts[MAX_STAGES];

    // Fragment tracking
    u8 frag_count_rx;     // Fragments seen at RX
    u8 frag_count_tx;     // Fragments seen at TX
    u8 has_first_frag:1;  // Have we seen offset=0?
    u8 has_last_frag:1;   // Have we seen MF=0?

    // Port info (from first fragment only)
    __be16 sport;
    __be16 dport;

    // Total payload for group
    u32 total_payload;
};
```

### Stage Tracking

Since UDP is connectionless, track single direction per group:

```
Single Direction (either src→dst or dst→src):
  [0] RX at rx-iface (netif_receive_skb) - any fragment
  [1] TX at tx-iface (dev_queue_xmit) - any fragment
```

**Fragment Group Completion**:
- Group is "complete" when both `has_first_frag` and `has_last_frag` are true
- Report group-level latency and drop status

### UDP-Specific Considerations

1. **No Response Matching**: UDP is connectionless, no request/response pairing
   - Deploy on both src and dst hosts
   - Merge results offline for end-to-end view

2. **Fragment Validation**:
   - First fragment (offset=0): Extract ports, mark `has_first_frag`
   - Last fragment (MF=0): Mark `has_last_frag`
   - Track fragment count at each stage

3. **IP ID Collision Handling**:
   - IP ID wraps at 65535, creating collision risk under high load
   - Primary mitigation: Include ports in group key when available
   - Secondary mitigation: LRU map with timeout-based expiration (default 1s)
   - Port lookup map stores {sip, dip, ip_id} -> {sport, dport} for non-first fragments

### Drop Detection Logic

| Has Stage | Missing Stage | Interpretation |
|-----------|---------------|----------------|
| RX (0) | TX (1) | Dropped internally |
| TX (1) only | RX (0) missing | Shouldn't happen (TX requires prior RX) |
| Partial frags | All frags | Some fragments dropped |

---

## Key Code Patterns to Reuse

### From icmp_drop_detector.py (Lines 49-363)

1. **BPF Text Template**: IP filter placeholders, interface arrays
2. **Flow Map**: `BPF_TABLE("lru_hash", struct flow_key, struct event_t, flow_map, 10240)`
3. **Stage Tracking**: `ts[MAX_STAGES]` array with timestamp at each point
4. **FlowTracker Class**: Python-side timeout and drop detection

### From vm_network_latency_details.py (Lines 253-315)

1. **TCP Parsing**: `parse_tcp_key()` with seq and payload_len extraction
2. **UDP Parsing**: `parse_udp_key()` with IP ID and fragment handling
3. **Header Extraction**: `get_ip_header()`, `get_transport_header()`

---

## Implementation Steps

### Phase 1: TCP Drop Detector

1. Copy `icmp_drop_detector.py` as base
2. Replace ICMP flow key with TCP flow key (5-tuple + seq + payload_len)
3. Update `parse_icmp_packet()` to `parse_tcp_packet()`
4. Add TCP direction detection (swap ports for canonical key)
5. Update CLI args: add `--src-port`, `--dst-port` filters
6. Test with `ping` equivalent: `nc` or `curl`

### Phase 2: UDP Drop Detector

1. Create new file with fragment group tracking
2. Implement `udp_group_key` and `udp_group_data` structures
3. Add fragment state machine (first/last fragment tracking)
4. Add fragment count comparison for partial drop detection
5. Implement group timeout and expiration
6. Test with `iperf -u` or DNS queries

### Phase 3: Testing & Validation

1. Test TCP with various packet sizes (small, large with TSO)
2. Test UDP with fragmented packets (> MTU)
3. Verify drop detection by:
   - Adding iptables DROP rules
   - Traffic control (`tc`) for artificial drops
4. Compare results with existing tools

---

## Verification Plan

1. **Unit Test**: Verify flow key parsing with known packets
2. **Integration Test**:
   - Run detector while generating traffic
   - Inject artificial drops via iptables
   - Verify detector reports correct drop location
3. **Stress Test**: High packet rate to check for IP ID collisions (UDP)

---

## Files

| Status | File | Description |
|--------|------|-------------|
| IMPLEMENTED | `measurement-tools/linux-network-stack/packet-drop/tcp_drop_detector.py` | TCP bidirectional drop detector |
| IMPLEMENTED | `measurement-tools/linux-network-stack/packet-drop/udp_drop_detector.py` | UDP fragment-group drop detector |
| REFERENCE | `icmp_drop_detector.py` | Base pattern for 4-stage tracking |
| REFERENCE | `vm_network_latency_details.py:253-315` | TCP/UDP parsing functions |

---

## Appendix: Kernel Implementation Analysis

### Why TCP Sequence Numbers Are Stable

In the Linux kernel, TCP sequence numbers are assigned at `tcp_sendmsg()` before data enters the network stack:

1. **Sequence Assignment** (`net/ipv4/tcp.c:tcp_sendmsg_locked()`):
   - `seq = tp->write_seq` assigned before segmentation
   - Each byte in the stream has a unique sequence number

2. **GSO/TSO Segmentation** (`net/core/skbuff.c:skb_segment()`):
   - Creates multiple sk_buffs from one large buffer
   - Each segment gets sequential sequence numbers
   - `new_skb->seq = old_seq + offset`

3. **Stable Through Path**:
   - Sequence numbers in TCP header never change
   - Only payload size varies due to segmentation

### UDP IP ID Behavior

1. **IP ID Assignment** (`net/ipv4/ip_output.c:ip_select_ident()`):
   - Assigned per-destination in modern kernels (to prevent fingerprinting)
   - Increments per flow, wraps at 65535

2. **Fragmentation** (`net/ipv4/ip_output.c:ip_fragment()`):
   - All fragments inherit parent's IP ID
   - MF (More Fragments) bit set on all but last
   - Offset field indicates position in original datagram

3. **Fragment Reassembly** (`net/ipv4/ip_fragment.c:ip_defrag()`):
   - Groups fragments by `{src_ip, dst_ip, ip_id, protocol}`
   - Timeout-based cleanup (default: 30 seconds)

### Pre-GSO vs Post-GSO Tracking Points

| Probe Point | Pre/Post GSO | Packet View |
|-------------|--------------|-------------|
| `tcp_sendmsg` | Pre | Application data chunk |
| `dev_queue_xmit` entry | Pre | 1 large GSO packet |
| `dev_queue_xmit` return | Post | N segments (if offload) |
| NIC driver TX | Post | Physical packets |

**Recommendation**: Track at `dev_queue_xmit` entry for simplest packet identification while still capturing internal drops.
