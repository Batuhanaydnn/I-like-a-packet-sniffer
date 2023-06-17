import socket
from scapy.all import *

def packet_handler_FTP(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == 21:
        src_id = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        data = packet[Raw].load
        print('----------------TCP----------------')
        print(f"Source IP: {src_id}")
        print(f"Destşnation IP: {dst_ip}")
        print(f"Source Port: {src_port}")
        print(f"Destination Port: {dst_port}")
        print(f"Data: {data}")


# def start_sniffer():
#     try:
#         sniff(filter="tcp port 21", prn=packet_handler_FTP, store=0)
#     except socket.error as e:
#         print(f"Erro occurred {e}")

# if __name__ == '__main__':
#     start_sniffer()