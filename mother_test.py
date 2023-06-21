from scapy.all import *
from main import packet_handlers

def test_packet_sniffer():
    packet = IP(src="192.168.0.1", dst="192.168.0.2") / TCP(sport=1234, dport=80) / Raw(b"Test packet")

    try:
        packet_handlers(packet)
    except Scapy_Exception as e:
        print("Scapy Error occurred:", e)
    except socket.error as se:
        if 'tcp' in se.strerror.lower():
            print("TCP Socket Error occurred:", se)
        elif 'udp' in se.strerror.lower():
            print("UDP Socket Error occurred:", se)
    except Exception as e:
        print("Error Occured", e)
        

if __name__ == '__main__':
    test_packet_sniffer()