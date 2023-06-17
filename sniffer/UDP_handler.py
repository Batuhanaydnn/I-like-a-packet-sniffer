from scapy.all import *

def packet_handeler_UDP(packet):
    if packet.haslayer(UDP):
        src_id = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        data = packet[UDP].payload
        print('----------------UDP----------------')
        print(f"Source IP: {src_id}")
        print(f"Destination IP: {dst_ip}")
        print(f"Source Port: {src_port}")
        print(f"Destination Port: {dst_port}")
        print(f"Data: {data}")

def start_UDP_sniffer():
    try:
        sniff(filter="udp", prn=packet_handeler_UDP)
    except scapy.error as e:
        print("UDP error occured")

if __name__ == '__main__':
    start_UDP_sniffer()
        