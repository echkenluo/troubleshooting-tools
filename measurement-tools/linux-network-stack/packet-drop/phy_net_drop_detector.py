#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Physical Network Drop Detector - Detect packet drops in physical network layer

This tool uses dual-endpoint UDP probing combined with NIC hardware counter
analysis to determine whether packet drops occur in the physical network
or kernel software stack.

Architecture:
  Sender Mode:
    1. Collect NIC statistics before/after test
    2. Send UDP probe packets with sequence numbers
    3. Request receiver statistics
    4. Analyze and output diagnosis report

  Receiver Mode:
    1. Collect NIC statistics
    2. Receive and track probe packets
    3. Report statistics to sender on request

Usage:
  Receiver side:
    sudo python phy_net_drop_detector.py --mode receiver --interface eth0 --port 5555

  Sender side:
    sudo python phy_net_drop_detector.py --mode sender --interface eth0 \\
        --peer 192.168.1.200 --port 5555 --duration 30 --rate 1000

Author: Claude Code
"""

from __future__ import print_function, division

import argparse
import os
import signal
import socket
import struct
import sys
import threading
import time

# Protocol constants
MAGIC_PROBE = 0x50485944  # "PHYD" - probe packet
MAGIC_CTRL  = 0x50485943  # "PHYC" - control packet

# Control packet types
CTRL_STATS_REQ = 1  # Request statistics from receiver
CTRL_STATS_RSP = 2  # Statistics response
CTRL_START     = 3  # Start test notification
CTRL_STOP      = 4  # Stop test notification
CTRL_ACK       = 5  # Acknowledgement

# Probe packet format: Magic(4B) + Seq(4B) + Timestamp(8B) = 16 bytes min
PROBE_HEADER_FMT = '!IIQ'
PROBE_HEADER_SIZE = struct.calcsize(PROBE_HEADER_FMT)

# Control packet format: Magic(4B) + Type(1B) + Payload(variable)
CTRL_HEADER_FMT = '!IB'
CTRL_HEADER_SIZE = struct.calcsize(CTRL_HEADER_FMT)


class NICStats(object):
    """NIC statistics collection from sysfs"""

    # Physical layer indicators (hardware drops)
    PHYSICAL_COUNTERS = [
        'rx_over_errors',     # RX FIFO overflow
        'rx_crc_errors',      # CRC checksum failures
        'rx_missed_errors',   # Hardware ring buffer drops
        'rx_fifo_errors',     # RX FIFO errors
        'rx_frame_errors',    # Frame alignment errors
        'rx_length_errors',   # Invalid frame length
        'tx_carrier_errors',  # Carrier signal lost
        'tx_aborted_errors',  # Transmission aborted
        'tx_fifo_errors',     # TX FIFO underrun
    ]

    # Software layer indicators (kernel drops)
    SOFTWARE_COUNTERS = [
        'rx_dropped',         # Software stack RX drops
        'tx_dropped',         # Software stack TX drops
        'rx_errors',          # Total RX errors (aggregate)
        'tx_errors',          # Total TX errors (aggregate)
    ]

    # Traffic counters
    TRAFFIC_COUNTERS = [
        'rx_packets',
        'tx_packets',
        'rx_bytes',
        'tx_bytes',
    ]

    def __init__(self, interface):
        self.interface = interface
        self.stats_path = '/sys/class/net/{}/statistics'.format(interface)
        if not os.path.exists(self.stats_path):
            raise ValueError('Interface {} not found'.format(interface))

    def _read_counter(self, name):
        """Read a single counter from sysfs"""
        path = os.path.join(self.stats_path, name)
        try:
            with open(path, 'r') as f:
                return int(f.read().strip())
        except (IOError, ValueError):
            return 0

    def collect(self):
        """Collect all statistics"""
        stats = {
            'physical': {},
            'software': {},
            'traffic': {},
            'timestamp': time.time(),
        }

        for name in self.PHYSICAL_COUNTERS:
            stats['physical'][name] = self._read_counter(name)

        for name in self.SOFTWARE_COUNTERS:
            stats['software'][name] = self._read_counter(name)

        for name in self.TRAFFIC_COUNTERS:
            stats['traffic'][name] = self._read_counter(name)

        return stats

    @staticmethod
    def compute_delta(before, after):
        """Compute delta between two stats snapshots"""
        delta = {
            'physical': {},
            'software': {},
            'traffic': {},
            'duration': after['timestamp'] - before['timestamp'],
        }

        for category in ['physical', 'software', 'traffic']:
            for key in before[category]:
                delta[category][key] = after[category][key] - before[category][key]

        return delta


class ProbeReceiver(object):
    """UDP probe packet receiver"""

    def __init__(self, interface, port, verbose=False):
        self.interface = interface
        self.port = port
        self.verbose = verbose
        self.nic_stats = NICStats(interface)

        # Probe tracking
        self.received_seqs = set()
        self.min_seq = None
        self.max_seq = None
        self.first_recv_time = None
        self.last_recv_time = None
        self.out_of_order = 0
        self.last_seq = -1

        # Statistics snapshots
        self.stats_before = None
        self.stats_after = None

        # Control
        self.running = False
        self.test_active = False
        self.sock = None

    def reset_tracking(self):
        """Reset probe tracking for new test"""
        self.received_seqs = set()
        self.min_seq = None
        self.max_seq = None
        self.first_recv_time = None
        self.last_recv_time = None
        self.out_of_order = 0
        self.last_seq = -1
        self.stats_before = None
        self.stats_after = None

    def handle_probe(self, data, addr):
        """Handle incoming probe packet"""
        if len(data) < PROBE_HEADER_SIZE:
            return

        magic, seq, timestamp = struct.unpack(PROBE_HEADER_FMT, data[:PROBE_HEADER_SIZE])
        if magic != MAGIC_PROBE:
            return

        now = time.time()

        # Track first packet - start collecting stats
        if self.min_seq is None:
            self.stats_before = self.nic_stats.collect()
            self.min_seq = seq
            self.first_recv_time = now
            self.test_active = True

        self.max_seq = max(self.max_seq or seq, seq)
        self.last_recv_time = now
        self.received_seqs.add(seq)

        # Track out-of-order
        if seq < self.last_seq:
            self.out_of_order += 1
        self.last_seq = seq

        if self.verbose and len(self.received_seqs) % 1000 == 0:
            print('[Receiver] Received {} probes'.format(len(self.received_seqs)))

    def handle_control(self, data, addr):
        """Handle control packet"""
        if len(data) < CTRL_HEADER_SIZE:
            return

        magic, ctrl_type = struct.unpack(CTRL_HEADER_FMT, data[:CTRL_HEADER_SIZE])
        if magic != MAGIC_CTRL:
            return

        if ctrl_type == CTRL_START:
            # Sender notifies test start
            self.reset_tracking()
            if self.verbose:
                print('[Receiver] Test started by sender')
            # Send ACK
            response = struct.pack(CTRL_HEADER_FMT, MAGIC_CTRL, CTRL_ACK)
            self.sock.sendto(response, addr)

        elif ctrl_type == CTRL_STOP:
            # Sender notifies test end
            if self.test_active:
                self.stats_after = self.nic_stats.collect()
                self.test_active = False
            if self.verbose:
                print('[Receiver] Test stopped by sender')
            # Send ACK
            response = struct.pack(CTRL_HEADER_FMT, MAGIC_CTRL, CTRL_ACK)
            self.sock.sendto(response, addr)

        elif ctrl_type == CTRL_STATS_REQ:
            # Sender requests statistics
            if self.stats_after is None:
                self.stats_after = self.nic_stats.collect()

            self.send_stats_response(addr)

    def send_stats_response(self, addr):
        """Send statistics response to sender"""
        # Build response payload
        # Format: received_count(4B) + min_seq(4B) + max_seq(4B) + out_of_order(4B)
        #         + stats_delta (physical counters + software counters)

        received_count = len(self.received_seqs)
        min_seq = self.min_seq if self.min_seq is not None else 0
        max_seq = self.max_seq if self.max_seq is not None else 0

        # Compute delta if we have both snapshots
        delta = None
        if self.stats_before and self.stats_after:
            delta = NICStats.compute_delta(self.stats_before, self.stats_after)

        # Build payload
        payload = struct.pack('!IIII', received_count, min_seq, max_seq, self.out_of_order)

        # Add NIC stats delta (physical counters)
        if delta:
            for name in NICStats.PHYSICAL_COUNTERS:
                payload += struct.pack('!Q', delta['physical'].get(name, 0))
            for name in NICStats.SOFTWARE_COUNTERS:
                payload += struct.pack('!Q', delta['software'].get(name, 0))
        else:
            # Send zeros if no delta available
            for _ in NICStats.PHYSICAL_COUNTERS:
                payload += struct.pack('!Q', 0)
            for _ in NICStats.SOFTWARE_COUNTERS:
                payload += struct.pack('!Q', 0)

        # Send response
        header = struct.pack(CTRL_HEADER_FMT, MAGIC_CTRL, CTRL_STATS_RSP)
        self.sock.sendto(header + payload, addr)

        if self.verbose:
            print('[Receiver] Sent stats: received={}, range=[{}, {}]'.format(
                received_count, min_seq, max_seq))

    def run(self):
        """Main receiver loop"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', self.port))
        self.sock.settimeout(1.0)

        self.running = True
        print('[Receiver] Listening on port {} (interface: {})'.format(
            self.port, self.interface))
        print('[Receiver] Press Ctrl+C to stop')

        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                if len(data) >= 4:
                    magic = struct.unpack('!I', data[:4])[0]
                    if magic == MAGIC_PROBE:
                        self.handle_probe(data, addr)
                    elif magic == MAGIC_CTRL:
                        self.handle_control(data, addr)
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break

        self.sock.close()
        print('[Receiver] Stopped')


class ProbeSender(object):
    """UDP probe packet sender with diagnosis"""

    def __init__(self, interface, peer, port, duration, rate, size, verbose=False):
        self.interface = interface
        self.peer = peer
        self.port = port
        self.duration = duration
        self.rate = rate
        self.size = max(size, PROBE_HEADER_SIZE)
        self.verbose = verbose

        self.nic_stats = NICStats(interface)
        self.sock = None

        # Sending tracking
        self.sent_count = 0
        self.send_start_time = None
        self.send_end_time = None

        # Statistics
        self.stats_before = None
        self.stats_after = None
        self.receiver_stats = None

    def send_control(self, ctrl_type, wait_ack=True, timeout=5.0):
        """Send control packet and optionally wait for ACK"""
        packet = struct.pack(CTRL_HEADER_FMT, MAGIC_CTRL, ctrl_type)
        self.sock.sendto(packet, (self.peer, self.port))

        if wait_ack:
            self.sock.settimeout(timeout)
            try:
                data, _ = self.sock.recvfrom(65535)
                if len(data) >= CTRL_HEADER_SIZE:
                    magic, rsp_type = struct.unpack(CTRL_HEADER_FMT, data[:CTRL_HEADER_SIZE])
                    if magic == MAGIC_CTRL and rsp_type == CTRL_ACK:
                        return True
            except socket.timeout:
                pass
        return False

    def request_receiver_stats(self):
        """Request and receive statistics from receiver"""
        packet = struct.pack(CTRL_HEADER_FMT, MAGIC_CTRL, CTRL_STATS_REQ)
        self.sock.sendto(packet, (self.peer, self.port))

        self.sock.settimeout(5.0)
        try:
            data, _ = self.sock.recvfrom(65535)
            if len(data) < CTRL_HEADER_SIZE:
                return None

            magic, rsp_type = struct.unpack(CTRL_HEADER_FMT, data[:CTRL_HEADER_SIZE])
            if magic != MAGIC_CTRL or rsp_type != CTRL_STATS_RSP:
                return None

            # Parse response
            payload = data[CTRL_HEADER_SIZE:]
            if len(payload) < 16:
                return None

            received_count, min_seq, max_seq, out_of_order = struct.unpack(
                '!IIII', payload[:16])

            # Parse NIC stats delta
            offset = 16
            physical_delta = {}
            for name in NICStats.PHYSICAL_COUNTERS:
                if offset + 8 <= len(payload):
                    physical_delta[name] = struct.unpack('!Q', payload[offset:offset+8])[0]
                    offset += 8

            software_delta = {}
            for name in NICStats.SOFTWARE_COUNTERS:
                if offset + 8 <= len(payload):
                    software_delta[name] = struct.unpack('!Q', payload[offset:offset+8])[0]
                    offset += 8

            return {
                'received_count': received_count,
                'min_seq': min_seq,
                'max_seq': max_seq,
                'out_of_order': out_of_order,
                'nic_delta': {
                    'physical': physical_delta,
                    'software': software_delta,
                }
            }
        except socket.timeout:
            return None

    def send_probes(self):
        """Send probe packets at specified rate"""
        interval = 1.0 / self.rate if self.rate > 0 else 0
        padding = b'\x00' * (self.size - PROBE_HEADER_SIZE)

        self.send_start_time = time.time()
        end_time = self.send_start_time + self.duration
        seq = 0

        print('[Sender] Sending probes for {} seconds at {} pps...'.format(
            self.duration, self.rate))

        next_send = self.send_start_time
        while time.time() < end_time:
            now = time.time()
            if now >= next_send:
                # Build and send probe
                timestamp = int(now * 1000000)  # microseconds
                packet = struct.pack(PROBE_HEADER_FMT, MAGIC_PROBE, seq, timestamp) + padding
                try:
                    self.sock.sendto(packet, (self.peer, self.port))
                    seq += 1
                    self.sent_count = seq
                except socket.error:
                    pass

                next_send += interval

                # Progress indicator
                if self.verbose and seq % 1000 == 0:
                    print('[Sender] Sent {} probes'.format(seq))
            else:
                # Short sleep to avoid busy waiting
                sleep_time = min(next_send - now, 0.001)
                if sleep_time > 0:
                    time.sleep(sleep_time)

        self.send_end_time = time.time()
        print('[Sender] Sent {} probes in {:.2f} seconds'.format(
            self.sent_count, self.send_end_time - self.send_start_time))

    def diagnose(self, sender_delta, receiver_stats):
        """Analyze results and produce diagnosis"""
        diagnosis = {
            'conclusion': 'UNKNOWN',
            'evidence': [],
            'root_cause': [],
            'recommendations': [],
        }

        # Calculate probe loss
        sent = self.sent_count
        received = receiver_stats['received_count']
        lost = sent - received
        loss_rate = (lost / sent * 100) if sent > 0 else 0

        # Get receiver NIC delta
        recv_phy = receiver_stats['nic_delta']['physical']
        recv_sw = receiver_stats['nic_delta']['software']

        # Get sender NIC delta
        send_phy = sender_delta['physical']
        send_sw = sender_delta['software']

        # Check for physical layer drops on receiver
        recv_phy_drops = sum([
            recv_phy.get('rx_over_errors', 0),
            recv_phy.get('rx_crc_errors', 0),
            recv_phy.get('rx_missed_errors', 0),
            recv_phy.get('rx_fifo_errors', 0),
        ])

        # Check for software layer drops on receiver
        recv_sw_drops = recv_sw.get('rx_dropped', 0)

        # Check for sender TX issues
        send_phy_drops = sum([
            send_phy.get('tx_carrier_errors', 0),
            send_phy.get('tx_aborted_errors', 0),
            send_phy.get('tx_fifo_errors', 0),
        ])
        send_sw_drops = send_sw.get('tx_dropped', 0)

        # Diagnosis logic
        if loss_rate < 0.01:
            # No significant loss
            diagnosis['conclusion'] = 'NO_DROP'
            diagnosis['evidence'].append('Probe loss rate: {:.4f}%'.format(loss_rate))

        elif recv_phy_drops > 0 and recv_phy_drops >= lost * 0.5:
            # Physical layer drops detected on receiver
            diagnosis['conclusion'] = 'PHYSICAL_NETWORK_DROP'
            diagnosis['evidence'].append('Probe loss: {} packets ({:.2f}%)'.format(lost, loss_rate))

            if recv_phy.get('rx_over_errors', 0) > 0:
                diagnosis['evidence'].append('Receiver rx_over_errors: +{}'.format(
                    recv_phy['rx_over_errors']))
                diagnosis['root_cause'].append('Receiver NIC ring buffer overflow')
                diagnosis['recommendations'].append('Increase RX ring buffer: ethtool -G {} rx 4096'.format(
                    self.interface))

            if recv_phy.get('rx_crc_errors', 0) > 0:
                diagnosis['evidence'].append('Receiver rx_crc_errors: +{}'.format(
                    recv_phy['rx_crc_errors']))
                diagnosis['root_cause'].append('Physical layer CRC errors (cable/connector issue)')
                diagnosis['recommendations'].append('Check network cables and connectors')

            if recv_phy.get('rx_missed_errors', 0) > 0:
                diagnosis['evidence'].append('Receiver rx_missed_errors: +{}'.format(
                    recv_phy['rx_missed_errors']))
                diagnosis['root_cause'].append('DMA processing delay (CPU or memory bottleneck)')
                diagnosis['recommendations'].append('Enable RPS/RFS for better CPU distribution')

        elif send_phy_drops > 0 or send_sw_drops > 0:
            # Sender side drops
            diagnosis['conclusion'] = 'SENDER_STACK_DROP'
            diagnosis['evidence'].append('Probe loss: {} packets ({:.2f}%)'.format(lost, loss_rate))

            if send_phy_drops > 0:
                diagnosis['evidence'].append('Sender TX physical errors: +{}'.format(send_phy_drops))
                diagnosis['root_cause'].append('Sender NIC TX hardware issue')

            if send_sw_drops > 0:
                diagnosis['evidence'].append('Sender tx_dropped: +{}'.format(send_sw_drops))
                diagnosis['root_cause'].append('Sender software stack drops (qdisc/driver)')
                diagnosis['recommendations'].append('Check sender qdisc queue length: tc qdisc show dev {}'.format(
                    self.interface))

        elif recv_sw_drops > 0:
            # Receiver software stack drops
            diagnosis['conclusion'] = 'RECEIVER_STACK_DROP'
            diagnosis['evidence'].append('Probe loss: {} packets ({:.2f}%)'.format(lost, loss_rate))
            diagnosis['evidence'].append('Receiver rx_dropped: +{}'.format(recv_sw_drops))
            diagnosis['root_cause'].append('Receiver kernel stack drops (use eth_drop.py for details)')
            diagnosis['recommendations'].append('Run: sudo python eth_drop.py --interface {} --type ipv4'.format(
                self.interface))

        elif lost > 0:
            # Lost packets but no counter evidence
            diagnosis['conclusion'] = 'PHYSICAL_NETWORK_DROP'
            diagnosis['evidence'].append('Probe loss: {} packets ({:.2f}%)'.format(lost, loss_rate))
            diagnosis['evidence'].append('No NIC counter increase at either endpoint')
            diagnosis['root_cause'].append('Packet dropped in transit (switch/router/cable)')
            diagnosis['recommendations'].append('Check intermediate network devices')
            diagnosis['recommendations'].append('Run packet capture at both ends for correlation')

        return diagnosis

    def print_report(self, sender_delta, receiver_stats, diagnosis):
        """Print formatted diagnosis report"""
        print('')
        print('=' * 80)
        print('Physical Network Drop Detector - Diagnosis Report')
        print('=' * 80)
        print('')
        print('Test Configuration:')
        print('  Sender:    {} ({})'.format(
            socket.gethostbyname(socket.gethostname()), self.interface))
        print('  Receiver:  {} ({})'.format(self.peer, self.interface))
        print('  Duration:  {:.1f} seconds'.format(
            self.send_end_time - self.send_start_time))
        print('  Probes:    {} packets'.format(self.sent_count))
        print('')

        print('-' * 80)
        print('Probe Statistics:')
        print('-' * 80)
        sent = self.sent_count
        received = receiver_stats['received_count']
        lost = sent - received
        loss_rate = (lost / sent * 100) if sent > 0 else 0
        print('  Packets Sent:      {}'.format(sent))
        print('  Packets Received:  {}'.format(received))
        print('  Packets Lost:      {}'.format(lost))
        print('  Loss Rate:         {:.4f}%'.format(loss_rate))
        if receiver_stats['out_of_order'] > 0:
            print('  Out of Order:      {}'.format(receiver_stats['out_of_order']))
        print('')

        print('-' * 80)
        print('NIC Counter Changes (Delta):')
        print('-' * 80)
        print('{:28s} {:>20s}    {:>20s}'.format('', 'Sender', 'Receiver'))

        print('  [Physical Layer]')
        recv_phy = receiver_stats['nic_delta']['physical']
        for name in NICStats.PHYSICAL_COUNTERS:
            send_val = sender_delta['physical'].get(name, 0)
            recv_val = recv_phy.get(name, 0)
            if send_val > 0 or recv_val > 0:
                print('    {:24s} {:>+20d}    {:>+20d}'.format(name, send_val, recv_val))

        print('  [Software Layer]')
        recv_sw = receiver_stats['nic_delta']['software']
        for name in NICStats.SOFTWARE_COUNTERS:
            send_val = sender_delta['software'].get(name, 0)
            recv_val = recv_sw.get(name, 0)
            if send_val > 0 or recv_val > 0:
                print('    {:24s} {:>+20d}    {:>+20d}'.format(name, send_val, recv_val))
        print('')

        print('-' * 80)
        print('DIAGNOSIS:')
        print('-' * 80)

        conclusion_map = {
            'NO_DROP': '[NO SIGNIFICANT DROPS]',
            'PHYSICAL_NETWORK_DROP': '[PHYSICAL NETWORK DROP DETECTED]',
            'SENDER_STACK_DROP': '[SENDER SOFTWARE STACK DROP]',
            'RECEIVER_STACK_DROP': '[RECEIVER SOFTWARE STACK DROP]',
            'UNKNOWN': '[UNKNOWN - INSUFFICIENT DATA]',
        }
        print('  {}'.format(conclusion_map.get(diagnosis['conclusion'], diagnosis['conclusion'])))
        print('')

        if diagnosis['evidence']:
            print('  Evidence:')
            for item in diagnosis['evidence']:
                print('    - {}'.format(item))
            print('')

        if diagnosis['root_cause']:
            print('  Root Cause Analysis:')
            for i, item in enumerate(diagnosis['root_cause'], 1):
                print('    {}. {}'.format(i, item))
            print('')

        if diagnosis['recommendations']:
            print('  Recommendations:')
            for i, item in enumerate(diagnosis['recommendations'], 1):
                print('    {}. {}'.format(i, item))
            print('')

        print('=' * 80)

    def run(self):
        """Main sender workflow"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        print('[Sender] Starting test to {} port {}'.format(self.peer, self.port))

        # Notify receiver to start
        print('[Sender] Notifying receiver to start...')
        if not self.send_control(CTRL_START, wait_ack=True):
            print('[Sender] Warning: No ACK from receiver (continuing anyway)')

        # Collect sender stats before
        self.stats_before = self.nic_stats.collect()

        # Send probes
        self.send_probes()

        # Collect sender stats after
        self.stats_after = self.nic_stats.collect()
        sender_delta = NICStats.compute_delta(self.stats_before, self.stats_after)

        # Small delay to let receiver process last packets
        time.sleep(0.5)

        # Notify receiver to stop
        print('[Sender] Notifying receiver to stop...')
        self.send_control(CTRL_STOP, wait_ack=True)

        # Request receiver statistics
        print('[Sender] Requesting receiver statistics...')
        self.receiver_stats = self.request_receiver_stats()

        if self.receiver_stats is None:
            print('[Sender] ERROR: Failed to get receiver statistics')
            self.sock.close()
            return 1

        # Diagnose
        diagnosis = self.diagnose(sender_delta, self.receiver_stats)

        # Print report
        self.print_report(sender_delta, self.receiver_stats, diagnosis)

        self.sock.close()
        return 0


def signal_handler(signum, frame):
    """Handle Ctrl+C"""
    print('\nInterrupted')
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description='Physical Network Drop Detector - Detect packet drops in physical network layer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Receiver side:
    sudo python %(prog)s --mode receiver --interface eth0 --port 5555

  Sender side:
    sudo python %(prog)s --mode sender --interface eth0 \\
        --peer 192.168.1.200 --port 5555 --duration 30 --rate 1000
''')

    parser.add_argument('--mode', '-m', required=True, choices=['sender', 'receiver'],
                        help='Operating mode: sender or receiver')
    parser.add_argument('--interface', '-i', required=True,
                        help='Network interface to monitor (e.g., eth0)')
    parser.add_argument('--port', '-p', type=int, default=5555,
                        help='UDP port for probe packets (default: 5555)')
    parser.add_argument('--peer', dest='peer',
                        help='Peer IP address (required for sender mode)')
    parser.add_argument('--duration', '-d', type=int, default=30,
                        help='Test duration in seconds (default: 30)')
    parser.add_argument('--rate', '-r', type=int, default=1000,
                        help='Probe packet rate in pps (default: 1000)')
    parser.add_argument('--size', '-s', type=int, default=64,
                        help='Probe packet size in bytes (default: 64)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')

    args = parser.parse_args()

    # Validate arguments
    if args.mode == 'sender' and not args.peer:
        parser.error('--peer is required for sender mode')

    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        if args.mode == 'receiver':
            receiver = ProbeReceiver(args.interface, args.port, args.verbose)
            receiver.run()
        else:
            sender = ProbeSender(
                args.interface, args.peer, args.port,
                args.duration, args.rate, args.size, args.verbose)
            return sender.run()
    except ValueError as e:
        print('Error: {}'.format(e))
        return 1
    except KeyboardInterrupt:
        print('\nInterrupted')
        return 0

    return 0


if __name__ == '__main__':
    sys.exit(main())
