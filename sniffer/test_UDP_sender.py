import unittest
from unittest import TestCase
from scapy.all import *
from UDP_handler import packet_handeler_UDP

class TestPacketHandelerUDP(TestCase):
    def test_packet_handeler_UDP(self):
        packet = IP(src="192.168.0.1", dst="192.168.0.2")/UDP(sport=12345, dport=80)/Raw(load="Test data")
        captured_output = io.StringIO()
        sys.stdout = captured_output
        packet_handeler_UDP(packet)
        sys.stdout = sys.__stdout__
        expected_output = '''----------------UDP----------------
Source IP: 192.168.0.1
Destination IP: 192.168.0.2
Source Port: 12345
Destination Port: 80
Data: Raw
'''
        self.assertEqual(captured_output.getvalue(), expected_output)

if __name__ == '__main__':
    unittest.main()