from scapy.all import sniff, ARP, BOOTP, ICMP, IP
from datetime import datetime

def packet_log(packet, proto_sniff, sniffer_log):
    now = datetime.now()
    src_mac = packet[ARP].hwsrc if ARP in packet else 'N/A'
    dst_mac = packet[ARP].hwdst if ARP in packet else 'N/A'
    src_ip = packet[IP].src if IP in packet else 'N/A'
    dst_ip = packet[IP].dst if IP in packet else 'N/A'
    protocol = 'ALL' if proto_sniff == "0" else proto_sniff.upper()
    log_entry = f"Time: {now}, Protocol: {protocol}, Source MAC: {src_mac}, Destination MAC: {dst_mac}, Source IP: {src_ip}, Destination IP: {dst_ip}"
    print(log_entry, file=sniffer_log)

def main():
    print("\n! Make sure to run this program as ROOT !\n")

    net_iface = input("* Enter the interface on which to run the sniffer (e.g. 'eth0'): ")
    pkt_to_sniff = int(input("* Enter the number of packets to capture (0 is infinity): "))
    time_to_sniff = int(input("* Enter the number of seconds to run the capture: "))
    proto_sniff = input("* Enter the protocol to filter by (arp|bootp|icmp|0 is all): ")
    file_name = input("* Please give a name to the log file: ")

    # Open log file
    with open(file_name, "a") as sniffer_log:
        print("\n* Starting the capture...")

        # Filter string based on user input
        filter_str = {
            'arp': 'arp',
            'bootp': 'bootp',
            'icmp': 'icmp',
            '0': None
        }.get(proto_sniff, None)

        # Sniff packets
        sniff(iface=net_iface, filter=filter_str, count=pkt_to_sniff if pkt_to_sniff > 0 else None, timeout=time_to_sniff, prn=lambda pkt: packet_log(pkt, proto_sniff, sniffer_log))

    print(f"\n* Please check the {file_name} file to see the captured packets.\n")

if __name__ == "__main__":
    main()

