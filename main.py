from scapy.all import *
from sniffer.TCP_handler import packet_handler_TCP
from sniffer.UDP_handler import packet_handeler_UDP
from sniffer.HTTP_handler import packet_handler_HTTP
from sniffer.HTTPS_handler import packet_handler_HTTPS
from sniffer.FTP_handeler import packet_handler_FTP
from sniffer.ICMP_handler import packet_handler_ICMP


def packet_handlers(packet):
    if packet.haslayer(TCP):
        packet_handler_TCP(packet)
    elif packet.haslayer(UDP):
        packet_handeler_UDP(packet)
    elif packet.haslayer(ICMP):
        packet_handler_ICMP(packet)
    elif packet.haslayer(Raw) and packet[TCP].dport and packet.haslayer(TCP)  == 80:
        packet_handler_HTTP(packet)
    elif packet.haslayer(Raw) and packet[TCP].dport and packet.haslayer(TCP) == 443:
        packet_handler_HTTPS(packet)
    elif packet.haslayer(Raw) and packet.haslayer(TCP) and packet[TCP].dport == 21:
        packet_handler_FTP(packet)

def start_sniffer():
    try:
        sniff(filter="tcp or udp or icmp or tcp port 80 or tcp port 443 tcp port 21", prn=packet_handlers, store=0)
    except Scapy_Exception as e:
        print("Scapy Error occurred: Make sure scapy is properly installed on your computer", e)
    except socket.error as se:
        if 'tcp' in se.strerror.lower():
            print("TCP Socket Error occurred", se)
        elif 'udp' in se.strerror.lower():
            print("UDP Socket Error occurred", se)
    # except FTP_Exception as fe:
    #     print("FTP Socket Error occurred", fe)
    # except ICMP_Exception as ie:
    #     print("ICMP Socket Error occurred", ie)
    # except HTTP_Exception as he:
    #     print("HTTP Socket Error occurred", he)
    # except HTTPS_Exception as hse:
    #     print("HTTPS Socket Error occurred", hse)
        

if __name__ == '__main__':
    start_sniffer()