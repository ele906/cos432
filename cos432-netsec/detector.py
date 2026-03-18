from sys import argv
import dpkt
from collections import defaultdict
import socket

def detect_anomaly(packet_capture):
    """
    Process a dpkt packet capture to determine if any syn scan is detected. For every IP address address that are
    detected as suspicious. We define "suspicious" as having sent more than three times as many SYN packets as the
    number of SYN+ACK packets received.
    :param packet_capture: dpkt packet capture object for processing
    """

    syn_sent = defaultdict(int)
    synack_received = defaultdict(int)

    for ts, buf in packet_capture:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            # not eth data
            continue

        # not ip data
        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data # it is IP data

        if not isinstance(ip.data, dpkt.tcp.TCP):
                # not tcp data
                continue

        tcp = ip.data

        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)

        syn = tcp.flags & dpkt.tcp.TH_SYN
        ack = tcp.flags & dpkt.tcp.TH_ACK

        if syn and not ack:
            syn_sent[src_ip] += 1
        elif syn and ack:
            synack_received[dst_ip] += 1

    res = []
    all_ips = set(syn_sent) | set(synack_received)

    for ip_addr in all_ips:
        if syn_sent[ip_addr] > 3 * synack_received[ip_addr]:
            res.append(ip_addr)

    print(res)



# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 2:
        print('usage: python detector.py capture.pcap')
        exit(-1)

    with open(argv[1], 'rb') as f:
        pcap_obj = dpkt.pcap.Reader(f)
        detect_anomaly(pcap_obj)

