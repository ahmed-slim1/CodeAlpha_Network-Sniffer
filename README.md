# Packet Sniffer using Scapy

## Overview

This Python script is designed to capture and log network packets using the Scapy library. Users can filter packets based on specific protocols (ARP, BOOTP, ICMP) or capture all packets. The captured data is logged to a specified file, including details such as source and destination MAC and IP addresses.

## Features

- Capture network packets from a specified interface.
- Filter packets by ARP, BOOTP, ICMP, or capture all packets.
- Log captured packets with timestamp, protocol, source and destination MAC addresses, and IP addresses.

## Requirements

- Python 3.x
- Scapy

To install Scapy, you can use pip:

- pip install scapy


##  User Input :
-- remember that these are just examples of what you can enter

* Enter the interface on which to run the sniffer (e.g. 'eth0'): eth0
* Enter the number of packets to capture (0 is infinity): 10
* Enter the number of seconds to run the capture: 30
* Enter the protocol to filter by (arp|bootp|icmp|0 is all): arp
* Please give a name to the log file: log.txt
