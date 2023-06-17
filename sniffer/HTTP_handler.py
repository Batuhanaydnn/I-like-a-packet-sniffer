from scapy.all import *

def packet_handler_HTTP(packet):
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
        if "HTTP" in raw_data:
            print("------------------HTTP PACKET------------------")
            print(raw_data)
def start_HTTP_sniffer():
    try:
        sniff(filter="tcp port 80", prn=packet_handler_HTTP, store=0)
    except scapy.error as e:
        print("HTTP error occured", e)

if __name__ == '__main__':
    start_HTTP_sniffer()
