import unittest
from unittest import TestCase
from scapy.all import *
from ICMP_handler import packet_handler_ICMP

class TestPacketHandlerICMP(TestCase):
    def test_packet_handler_ICMP(self):
        packet = IP(dst="192.168.0.1")/ICMP()
        captured_output = io.StringIO()
        sys.stdout = captured_output
        packet_handler_ICMP(packet)
        sys.stdout = sys.__stdout__
        expected_output = packet.summary() + "\n"
        self.assertEqual(captured_output.getvalue(), expected_output)

if __name__ == '__main__':
    unittest.main()