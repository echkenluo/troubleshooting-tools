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
   `{src_ip, dst_ip, src_port, dst_port, expected_ack, payload_len}`

   The `expected_ack` field is calculated differently for Request and Reply:
   - **Request**: `expected_ack = tcp_seq + payload_len + SYN_adj + FIN_adj`
   - **Reply**: `expected_ack = tcp_ack_seq` (used to match Request's expected_ack)

   This approach enables bidirectional tracking:
   - Request packet creates entry with calculated expected_ack
   - Reply packet's ack_seq matches the Request's expected_ack
   - SYN and FIN flags each consume 1 sequence number

4. **TCP Cumulative ACK Limitation**:

   **IMPORTANT**: TCP uses cumulative ACK, meaning one ACK confirms all data
   up to a certain sequence number. This affects bidirectional tracking:

   ```
   Scenario: Server sends 3 packets to client
     Packet 1: seq=100, len=100 → expected_ack=200
     Packet 2: seq=200, len=100 → expected_ack=300
     Packet 3: seq=300, len=100 → expected_ack=400

   Client receives all 3, sends ONE ACK:
     ACK = 400 (confirms all data up to byte 400)

   Result:
     - Packet 3 matches (expected_ack=400 == ack_seq=400) ✓
     - Packet 1 & 2 have NO matching Reply ✗
   ```

   **Impact by Traffic Pattern**:
   | Traffic Pattern | Bidirectional Mode | Internal-Only Mode |
   |-----------------|-------------------|-------------------|
   | Long connection, continuous flow (iperf3) | Most packets match | All packets match |
   | Short connection, burst data (HTTP GET) | Only last packet matches | All packets match |
   | Request-response (single packet each) | All packets match | All packets match |

   **Recommended Usage**:
   - Use `--internal-only` for bulk TCP traffic (file transfers, streaming)
   - Use default bidirectional mode for request-response protocols
   - SYN/SYN-ACK handshake always matches correctly in both modes

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

---

## Code Review Summary (2026-01-21)

### Overall Assessment

| Tool | Drop Tracking | Latency Tracking | Rating |
|------|--------------|------------------|--------|
| ICMP | Complete | Complete | ⭐⭐⭐⭐⭐ |
| UDP | Complete | Internal only | ⭐⭐⭐⭐ |
| TCP | Limited | Limited | ⭐⭐⭐ |

---

## UDP Implementation Review

### Data Fields Analysis

| Field | Purpose | Sufficient |
|-------|---------|------------|
| `ts[RX]`, `ts[TX]` | Timestamps | ✅ Drop tracking |
| `frag_count_rx`, `frag_count_tx` | Fragment counts | ✅ Partial drop detection |
| `has_first_frag`, `has_last_frag` | Fragment completeness | ✅ Group integrity |
| `ip_id` | Packet identifier | ✅ Cross-host correlation |
| `sport`, `dport` | Ports | ✅ Application layer correlation |
| `total_payload` | Payload size | ✅ Auxiliary validation |

### Drop Tracking Capability

**Host Internal Drop Detection**: ✅ Fully supported
- Has `ts[RX]` but no `ts[TX]` → Internal drop
- Fragment count mismatch (`frag_count_rx != frag_count_tx`) → Partial fragment drop

**Cross-Host Physical Network Drop Detection**: ✅ Data sufficient
- Sender side: `ts[TX]` + `ip_id` + `sport:dport`
- Receiver side: `ts[RX]` + `ip_id` + `sport:dport`
- Correlation method: Match by `{sip, dip, ip_id, sport, dport}` 5-tuple
- **Requires**: Offline merge of data from both hosts

### Latency Tracking Capability

| Scenario | Capability | Issue |
|----------|------------|-------|
| Host internal latency | ✅ `ts[TX] - ts[RX]` | None |
| Cross-host end-to-end latency | ❌ | Clock not synchronized |

**Cross-Host Latency Challenge**:
- Sender `ts[TX]` and receiver `ts[RX]` use different host clocks
- NTP synchronization error typically 1-10ms
- Unacceptable for measuring <1ms internal latency

**Potential Solutions**:
1. **PTP precise clock sync**: Requires hardware support, error can be <1μs
2. **RTT mode**: sender→receiver→sender, calculate RTT/2
3. **Relative latency analysis**: Compare latency trends on same host, not absolute values

---

## TCP Implementation Review

### seq+len ACK Matching Theory

**Theoretical Basis** (RFC 793):
```
Sender: sends seq=X, payload_len=N
Receiver: replies ack_seq = X + N (confirms bytes X to X+N-1)
```

**Behavior with GSO/GRO Enabled**:
```
VM sends: Large packet (64KB GSO)
    ↓
Host TX: dev_queue_xmit sees large packet (pre-GSO)
    ↓
Physical NIC: Hardware segmentation (post-GSO)
    ↓
Physical network transmission
    ↓
Receiver physical NIC: Receives multiple small packets
    ↓
Receiver Host RX: GRO merges to large packet (netif_receive_skb)
    ↓
VM receives: Large packet
```

**Key Insight**:
- Both sender `dev_queue_xmit` and receiver `netif_receive_skb` see **large packets** (pre-GSO/post-GRO)
- seq+len matching should theoretically work ✅

### iperf3 Traffic Analysis

Based on tcpdump analysis, with GSO/GRO enabled during iperf3:
- Sender sends large packets (65KB)
- Receiver sends independent ACK for each large packet

```
Out: seq 241158:306318, length 65160 → expected_ack = 306318
Out: seq 306318:371478, length 65160 → expected_ack = 371478
Out: seq 371478:372230, length 752   → expected_ack = 372230

In: ack 306318  ← Matches Packet 1 ✓
In: ack 371478  ← Matches Packet 2 ✓
In: ack 372230  ← Matches Packet 3 ✓
```

**Conclusion**: In normal GSO/GRO configuration, each large packet should match its Reply.

### Troubleshooting Match Failures

If test shows match failures:

1. **Direction Issue**: Verify `src-ip`/`dst-ip` setting
   - If `src-ip` = server, `dst-ip` = client
   - "Request" = ACK packets from server→client (small)
   - "Reply" = data packets from client→server (large)
   - ACK matching logic doesn't apply in this case

2. **Environment**: Verify detector runs on correct host (hypervisor with data flow)

3. **Debug**: Use `--verbose` to check actual expected_ack and ack_seq values

4. **Validate**: Compare with tcpdump data to verify matching logic

### Complex TCP Scenarios

**Streaming Protocols** (HTTP streaming, video, etc.):
- Data is continuously sent one-way
- ACKs are cumulative

**Current Implementation Limitations**:
- Only last packet of each burst matches Reply
- Intermediate packets report as "external drop" after timeout (false positive)

**Solutions**:
| Solution | Status | Description |
|----------|--------|-------------|
| `--internal-only` mode | ✅ Implemented | Only track RX→TX, skip Reply |
| ACK range matching | ❌ Not implemented | If `ack_seq >= expected_ack`, treat as match |
| Pure drop detection | ❌ Not implemented | Use TCP retransmission as drop indicator |

---

## Future Improvement Suggestions

### High Priority

1. **BPF API Update**: Change `bpf_probe_read` to `bpf_probe_read_kernel` for better compatibility on kernel 4.19+

2. **UDP Cross-Host Correlation Tool**: Create offline tool to merge data from both hosts
   ```
   Input: sender.log + receiver.log
   Output: end-to-end drop analysis
   Correlation key: {sip, dip, ip_id, sport, dport}
   ```

3. **Documentation**: Clearly document TCP detector's applicable scenarios and limitations

### Medium Priority

4. **TCP Retransmission Tracking Mode**: More reliable drop detection

   **Principle**: TCP retransmission is the most reliable drop indicator - when sender retransmits,
   it means the original packet was definitely lost (or ACK was lost).

   **Implementation Approach**:
   ```
   Probe points:
     - kprobe:__tcp_retransmit_skb (kernel retransmission function)
     - kprobe:tcp_retransmit_timer (RTO timeout retransmission)
     - tracepoint:tcp:tcp_retransmit_skb (if available)

   Data to capture:
     - sk: socket pointer (identifies connection)
     - seq: retransmitted sequence number
     - end_seq: end of retransmitted data
     - timestamp: when retransmission occurred
   ```

   **Advantages over current approach**:
   | Aspect | Current ACK Matching | Retransmission Tracking |
   |--------|---------------------|------------------------|
   | Drop detection accuracy | May have false positives | 100% accurate |
   | Cumulative ACK issue | Affected | Not affected |
   | Works for bulk transfer | Limited | Full support |
   | Latency measurement | Yes (RTT) | No (only drop detection) |

   **Kernel code path** (`net/ipv4/tcp_output.c`):
   ```c
   // tcp_retransmit_skb() is called when:
   // 1. RTO timer expires (no ACK received in time)
   // 2. Fast retransmit (3 duplicate ACKs received)
   // 3. SACK-based selective retransmit

   int __tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
   {
       // skb->seq = starting sequence number
       // TCP_SKB_CB(skb)->end_seq = ending sequence number
       // This tells us exactly which bytes were retransmitted
   }
   ```

   **Drop location inference**:
   - If Request was seen at ReqTX but triggers retransmission → External drop
   - If Request was NOT seen at ReqTX but retransmits → Internal drop (before TX)

5. **ACK Range Matching**: Extend bidirectional mode to handle cumulative ACK

   **Problem**: Current implementation uses exact match (`ack_seq == expected_ack`),
   but TCP cumulative ACK means `ack_seq` confirms ALL data up to that point.

   **Current behavior**:
   ```
   Packet 1: expected_ack = 200
   Packet 2: expected_ack = 300
   Packet 3: expected_ack = 400

   ACK received: ack_seq = 400

   Result: Only Packet 3 matches ✗
   ```

   **Proposed solution**: Range-based matching
   ```
   For each pending Request packet:
       If ack_seq >= expected_ack:
           Mark as matched (ACK confirms this packet was received)
   ```

   **Implementation changes**:
   ```python
   # Current: exact match
   def find_matching_request(ack_seq):
       return flow_map.get(ack_seq)  # Exact key lookup

   # Proposed: range match
   def find_matching_requests(ack_seq):
       matched = []
       for key, flow in flow_map.items():
           if flow.expected_ack <= ack_seq:
               matched.append(flow)
       return matched
   ```

   **BPF implementation challenge**:
   - BPF map lookup is O(1) with exact key
   - Range matching requires iteration, which is expensive
   - Possible solutions:
     1. Move range matching to userspace (Python)
     2. Use BPF array map with seq as index (limited range)
     3. Accept the limitation and recommend `--internal-only` for bulk

   **Trade-offs**:
   | Aspect | Exact Match | Range Match |
   |--------|-------------|-------------|
   | Performance | O(1) lookup | O(n) iteration |
   | Accuracy | Misses cumulative ACK | Handles all cases |
   | BPF complexity | Simple | Complex or userspace |
   | Memory | Single entry per packet | May match multiple |

### Low Priority

6. **TCP Timestamp RTT**: Use TCP timestamp option (RFC 7323)
   ```
   - tsval: send timestamp
   - tsecr: echoed timestamp
   - Receiver can calculate precise RTT
   ```

7. **SACK Analysis**: Use TCP SACK option for precise drop info

   **Background**: TCP Selective Acknowledgment (SACK, RFC 2018) allows receiver to
   report exactly which segments were received, even if they arrived out of order.

   **SACK Option Format**:
   ```
   Kind: 5
   Length: Variable (8n + 2 bytes, where n = number of blocks)

   +--------+--------+
   | Kind=5 | Length |
   +--------+--------+--------+--------+
   |     Left Edge of 1st Block        |
   +--------+--------+--------+--------+
   |    Right Edge of 1st Block        |
   +--------+--------+--------+--------+
   |              ...                  |
   +--------+--------+--------+--------+
   ```

   **How SACK reveals drops**:
   ```
   Sender sends: seq 100-200, 200-300, 300-400, 400-500
   Receiver gets: seq 100-200, 300-400, 400-500 (seq 200-300 lost)

   Receiver sends ACK with:
     - ack_seq = 200 (cumulative ACK up to hole)
     - SACK blocks: [300-400], [400-500] (received after hole)

   Sender knows:
     - Bytes 0-200: confirmed received
     - Bytes 200-300: MISSING (the gap before SACK blocks)
     - Bytes 300-500: received (in SACK blocks)
   ```

   **Impact on current tracking**:

   | Scenario | Without SACK Analysis | With SACK Analysis |
   |----------|----------------------|-------------------|
   | Packet 1 (seq 100-200) | ✅ ack_seq=200 matches | ✅ Same |
   | Packet 2 (seq 200-300) | ❌ No ACK, timeout as "drop" | ✅ Identified as actual drop |
   | Packet 3 (seq 300-400) | ❌ ack_seq=200 < expected(400) | ✅ In SACK block, received |
   | Packet 4 (seq 400-500) | ❌ ack_seq=200 < expected(500) | ✅ In SACK block, received |

   **Implementation approach**:
   ```c
   // Parse SACK option from TCP header
   struct sack_block {
       u32 left_edge;   // Start of received range
       u32 right_edge;  // End of received range
   };

   static int parse_sack_option(struct tcphdr *tcp, struct sack_block *blocks, int max_blocks)
   {
       u8 *opt = (u8 *)(tcp + 1);
       int opt_len = (tcp->doff * 4) - sizeof(*tcp);
       int i = 0, num_blocks = 0;

       while (i < opt_len && num_blocks < max_blocks) {
           u8 kind = opt[i];
           if (kind == 0) break;           // End of options
           if (kind == 1) { i++; continue; } // NOP
           if (kind == 5) {                // SACK
               u8 len = opt[i + 1];
               int n = (len - 2) / 8;      // Number of blocks
               for (int j = 0; j < n && num_blocks < max_blocks; j++) {
                   blocks[num_blocks].left_edge = ntohl(*(u32 *)&opt[i + 2 + j*8]);
                   blocks[num_blocks].right_edge = ntohl(*(u32 *)&opt[i + 6 + j*8]);
                   num_blocks++;
               }
           }
           i += opt[i + 1];  // Skip to next option
       }
       return num_blocks;
   }
   ```

   **Matching logic with SACK**:
   ```python
   def check_packet_status(expected_ack, ack_seq, sack_blocks):
       # Check cumulative ACK first
       if expected_ack <= ack_seq:
           return "RECEIVED"

       # Check if in any SACK block
       for left, right in sack_blocks:
           if left <= expected_ack <= right:
               return "RECEIVED_OUT_OF_ORDER"

       # Not in cumulative ACK or SACK blocks
       return "POSSIBLY_DROPPED"
   ```

   **Advantages of SACK analysis**:
   - Precise drop location: Know exactly which seq range was lost
   - No false positives: Packets in SACK blocks are confirmed received
   - Works with reordering: Distinguishes drop from out-of-order delivery

   **Limitations**:
   - Requires SACK negotiation (most modern TCP stacks enable by default)
   - BPF stack limit: Parsing TCP options requires careful bounds checking
   - Complexity: Option parsing adds code complexity

8. **UDP PTP Latency Sync**: Hardware timestamp support for cross-host latency
