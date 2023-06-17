import socket
from scapy.all import *

def packet_handler_TCP(packet):
    if packet.haslayer(TCP):
        src_id = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        data = packet[TCP].payload
        print('----------------TCP----------------')
        print(f"Source IP: {src_id}")
        print(f"Destination IP: {dst_ip}")
        print(f"Source Port: {src_port}")
        print(f"Destination Port: {dst_port}")
        print(f"Data: {data}")


def start_sniffer():
    try:
        sniff(filter="tcp", prn=packet_handler, store=0)
    except socket.error as e:
        print(f"Erro occurred {e}")

if __name__ == '__main__':
    start_sniffer()