import unittest
from unittest import TestCase
from scapy.all import *
from TCP_handler import packet_handler_TCP

class TestPacketHandlerTCP(TestCase):
    def test_packet_handler_TCP(self):
        packet = IP(src="192.168.0.1", dst="192.168.0.2")/TCP(sport=12345, dport=80)/Raw(load="Test data")
        captured_output = io.StringIO()
        sys.stdout = captured_output
        packet_handler_TCP(packet)
        sys.stdout = sys.__stdout__
        expected_output = '''----------------TCP----------------
Source IP: 192.168.0.1
Destination IP: 192.168.0.2
Source Port: 12345
Destination Port: 80
Data: Raw
'''
        self.assertEqual(captured_output.getvalue(), expected_output)

if __name__ == '__main__':
    unittest.main()