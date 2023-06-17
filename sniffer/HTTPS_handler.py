from scapy.all import *

def packet_handler_HTTPS(packet):
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
        if "HTTPS" in raw_data:
            print("------------------HTTPS PACKET------------------")
            print(raw_data)
def start_HTTPS_sniffer():
    try:
        sniff(filter="tcp port 443", prn=packet_handler_HTTPS, store=0)
    except scapy.error as e:
        print("HTTPS error occured", e)

if __name__ == '__main__':
    start_HTTPS_sniffer()
