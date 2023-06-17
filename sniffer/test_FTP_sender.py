import unittest
from scapy.all import *
from FTP_handeler import packet_handler_FTP

class TestFTPHandler(unittest.TestCase):
    def test_packet_handler_FTP(self):

        packet = IP(src="192.169.0.1", dst="192.168.0.2") / TCP(sport=4444, dport=23) /Raw(b"FTP packet")

        result = packet_handler_FTP(packet)

        self.assertEqual(result, 'Expected Result')

if __name__ == '__main__':
    unittest.main()

