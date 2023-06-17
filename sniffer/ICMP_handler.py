from scapy.all import *

def packet_handler_ICMP(packet):
    if packet.haslayer(ICMP):
        print(packet.summary())

# def start_UDP_sniffer():
#     try:
#         sniff(filter="icmp", prn=packet_handler_ICMP)
#     except scapy.error as e:
#         print("ICMP error occured")

# if __name__ == '__main__':
#     start_UDP_sniffer()
