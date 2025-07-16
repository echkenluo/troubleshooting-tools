# Enhanced eth_drop.py Design Document

## Overview
This document outlines the design for enhancing the `eth_drop.py` tool to provide comprehensive Ethernet packet drop analysis with advanced protocol filtering, VLAN support, and detailed header parsing.

## Current Implementation Issues

### 1. Protocol Filtering Problems
- Inconsistent protocol filtering logic between different protocol types
- Missing support for custom EtherType values (e.g., 0x9898)
- Incomplete ARP/RARP header parsing and display
- Limited support for non-IP protocols

### 2. VLAN Processing Issues
- VLAN header parsing exists but is not consistently applied
- Protocol extraction from VLAN-encapsulated packets needs refinement
- Double VLAN (QinQ) support is partially implemented but not fully tested

### 3. Display Format Issues
- Inconsistent output formatting across different protocol types
- Missing protocol-specific header information
- ARP/RARP packets show incomplete information

## Enhanced Design Requirements

### 1. Protocol Filtering System

#### Supported Protocol Types
- **arp**: ARP packets (EtherType 0x0806)
- **rarp**: RARP packets (EtherType 0x8035)
- **ipv4**: IPv4 packets (EtherType 0x0800)
- **ipv6**: IPv6 packets (EtherType 0x86DD)
- **lldp**: LLDP packets (EtherType 0x88CC)
- **flow_control**: Ethernet Flow Control (EtherType 0x8808)
- **other**: All other protocol types
- **Custom EtherType**: User-specified hex values (e.g., 0x9898)

#### Protocol Mapping Table
```
Protocol Name    | EtherType | Description
-----------------|-----------|-------------
arp             | 0x0806    | Address Resolution Protocol
rarp            | 0x8035    | Reverse Address Resolution Protocol
ipv4            | 0x0800    | Internet Protocol v4
ipv6            | 0x86DD    | Internet Protocol v6
lldp            | 0x88CC    | Link Layer Discovery Protocol
flow_control    | 0x8808    | Ethernet Flow Control
other           | N/A       | All other protocols
```

### 2. VLAN Support Architecture

#### VLAN Header Structure
```c
struct vlan_hdr {
    __be16 h_vlan_TCI;              // Tag Control Information
    __be16 h_vlan_encapsulated_proto; // Inner protocol
};
```

#### VLAN Processing Logic
1. **Detection**: Check if outer EtherType is 0x8100 (802.1Q)
2. **Extraction**: Parse VLAN ID (12 bits) and Priority (3 bits) from TCI
3. **Protocol Resolution**: Extract inner protocol from encapsulated header
4. **Double VLAN**: Support QinQ (0x8100 nested in 0x8100)

#### VLAN Information Display
- VLAN ID (0-4095)
- VLAN Priority (0-7)
- Inner protocol type
- VLAN tag presence indicator in output

### 3. Protocol-Specific Header Parsing

#### ARP/RARP Header Parsing
```c
struct arp_hdr {
    __be16 ar_hrd;    // Hardware type
    __be16 ar_pro;    // Protocol type
    __u8 ar_hln;      // Hardware address length
    __u8 ar_pln;      // Protocol address length
    __be16 ar_op;     // Operation code
    __u8 ar_sha[6];   // Sender hardware address
    __u8 ar_sip[4];   // Sender IP address
    __u8 ar_tha[6];   // Target hardware address
    __u8 ar_tip[4];   // Target IP address
};
```

#### IPv4 Header Parsing
```c
struct iphdr {
    __u8 ihl:4;       // Internet Header Length
    __u8 version:4;   // Version
    __u8 tos;         // Type of Service
    __be16 tot_len;   // Total Length
    __be16 id;        // Identification
    __be16 frag_off;  // Fragment Offset
    __u8 ttl;         // Time to Live
    __u8 protocol;    // Protocol
    __sum16 check;    // Header Checksum
    __be32 saddr;     // Source Address
    __be32 daddr;     // Destination Address
};
```

#### IPv6 Header Parsing
```c
struct ipv6hdr {
    __u8 version:4;   // Version
    __u8 priority:4;  // Traffic Class
    __u8 flow_lbl[3]; // Flow Label
    __be16 payload_len; // Payload Length
    __u8 nexthdr;     // Next Header
    __u8 hop_limit;   // Hop Limit
    struct in6_addr saddr; // Source Address
    struct in6_addr daddr; // Destination Address
};
```

### 4. Output Format Specification

#### Common Header Information
- Timestamp (HH:MM:SS)
- Process ID
- Process Name
- Device Interface
- VLAN Information (if present)

#### Protocol-Specific Output Formats

##### ARP/RARP Packets
```
[Timestamp] [PID] [Process] [VLAN info] ARP/RARP PACKET
Ethernet Header:
  Source MAC: xx:xx:xx:xx:xx:xx
  Dest MAC:   xx:xx:xx:xx:xx:xx
ARP Header:
  Hardware Type: 0x0001 (Ethernet)
  Protocol Type: 0x0800 (IPv4)
  Operation:     Request/Reply
  Sender MAC:    xx:xx:xx:xx:xx:xx
  Sender IP:     xxx.xxx.xxx.xxx
  Target MAC:    xx:xx:xx:xx:xx:xx
  Target IP:     xxx.xxx.xxx.xxx
```

##### IPv4 Packets
```
[Timestamp] [PID] [Process] [VLAN info] IPv4 PACKET
Ethernet Header:
  Source MAC: xx:xx:xx:xx:xx:xx
  Dest MAC:   xx:xx:xx:xx:xx:xx
IPv4 Header:
  Version:    4
  IHL:        5
  ToS:        0x00
  Length:     xxxx
  ID:         0xxxxx
  Flags:      xxx
  TTL:        xxx
  Protocol:   xxx (TCP/UDP/ICMP)
  Source IP:  xxx.xxx.xxx.xxx
  Dest IP:    xxx.xxx.xxx.xxx
```

##### IPv6 Packets
```
[Timestamp] [PID] [Process] [VLAN info] IPv6 PACKET
Ethernet Header:
  Source MAC: xx:xx:xx:xx:xx:xx
  Dest MAC:   xx:xx:xx:xx:xx:xx
IPv6 Header:
  Version:     6
  Traffic Class: 0x00
  Flow Label:  0x00000
  Payload Len: xxxx
  Next Header: xxx
  Hop Limit:   xxx
  Source IP:   xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
  Dest IP:     xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
```

##### Other Protocols
```
[Timestamp] [PID] [Process] [VLAN info] OTHER PROTOCOL
Ethernet Header:
  Source MAC: xx:xx:xx:xx:xx:xx
  Dest MAC:   xx:xx:xx:xx:xx:xx
  EtherType:  0xXXXX
```

### 5. Command Line Interface

#### Enhanced Argument Structure
```bash
./eth_drop.py [OPTIONS]

Options:
  --type TYPE           Protocol type filter (arp|rarp|ipv4|ipv6|lldp|flow_control|other|0xXXXX)
  --src IP             Source IP address filter (IPv4/IPv6)
  --dst IP             Destination IP address filter (IPv4/IPv6)
  --src-port PORT      Source port filter (TCP/UDP)
  --dst-port PORT      Destination port filter (TCP/UDP)
  --vlan-id VLAN       VLAN ID filter
  --interface IFACE    Network interface filter
  --verbose            Enable verbose output with full headers
  --no-stack-trace     Disable stack trace output
```

#### Usage Examples
```bash
# Filter ARP packets only
./eth_drop.py --type arp

# Filter custom protocol type
./eth_drop.py --type 0x9898

# Filter VLAN packets with specific VLAN ID
./eth_drop.py --vlan-id 100

# Filter IPv4 packets with source IP
./eth_drop.py --type ipv4 --src 192.168.1.100
```

### 6. Implementation Architecture

#### BPF Program Structure
```c
// Protocol filtering logic
static inline bool should_capture_packet(u16 protocol, u16 filter_protocol);

// VLAN header parsing
static inline int parse_vlan_header(struct sk_buff *skb, struct vlan_info *vlan);

// Protocol-specific parsing functions
static inline int parse_arp_header(struct sk_buff *skb, struct arp_data *arp);
static inline int parse_ipv4_header(struct sk_buff *skb, struct ipv4_data *ip);
static inline int parse_ipv6_header(struct sk_buff *skb, struct ipv6_data *ip);
```

#### Data Structure Enhancements
```c
struct packet_data_t {
    // Common fields
    u64 timestamp;
    u32 pid;
    char comm[16];
    char ifname[16];
    u32 stack_id;
    
    // Ethernet fields
    u8 eth_src[6];
    u8 eth_dst[6];
    u16 eth_type;
    
    // VLAN fields
    u16 vlan_id;
    u16 vlan_priority;
    u16 inner_protocol;
    
    // Protocol-specific union
    union {
        struct arp_data arp;
        struct ipv4_data ipv4;
        struct ipv6_data ipv6;
        struct other_data other;
    } proto;
};
```

### 7. Error Handling and Edge Cases

#### Error Conditions
1. **Invalid packet structure**: Graceful handling of malformed packets
2. **Memory access errors**: Proper bounds checking in BPF program
3. **Unknown protocols**: Fallback to "other" category
4. **Nested VLAN tags**: Support for QinQ scenarios

#### Performance Considerations
1. **Efficient filtering**: Early packet rejection for non-matching protocols
2. **Minimal memory copying**: Direct packet parsing without unnecessary copies
3. **Stack trace optimization**: Conditional stack trace collection

### 8. Testing Strategy

#### Test Cases
1. **Basic protocol filtering**: Test each supported protocol type
2. **VLAN support**: Single and double VLAN tag scenarios
3. **Custom EtherType**: Test with various custom protocol values
4. **Edge cases**: Malformed packets, unknown protocols
5. **Performance**: High packet rate scenarios

#### Test Environment
- Virtual network interfaces
- Packet injection tools
- VLAN configuration testing
- Protocol conformance testing

## Implementation Priority

1. **High Priority**: Protocol filtering system and VLAN support
2. **Medium Priority**: Enhanced output formatting and header parsing
3. **Low Priority**: Performance optimizations and advanced features

## Conclusion

This enhanced design provides a robust foundation for comprehensive Ethernet packet drop analysis with proper protocol filtering, VLAN support, and detailed header information display. The modular architecture allows for easy extension and maintenance while ensuring high performance in production environments.