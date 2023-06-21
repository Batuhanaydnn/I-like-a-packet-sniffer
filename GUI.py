from PyQt5.QtWidgets import QApplication, QLabel, QMainWindow, QPushButton
from scapy.all import *
from sniffer.TCP_handler import packet_handler_TCP
from sniffer.UDP_handler import packet_handeler_UDP
from sniffer.HTTP_handler import packet_handler_HTTP
from sniffer.HTTPS_handler import packet_handler_HTTPS
from sniffer.FTP_handeler import packet_handler_FTP
from sniffer.ICMP_handler import packet_handler_ICMP

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("My Packet Snıffer")
        self.setGeometry(100, 100, 400, 200)

        # Create a button to start the sniffer
        self.start_button = QPushButton("Start Sniffer", self)
        self.start_button.move(150, 50)
        self.start_button.clicked.connect(self.start_sniffer)

        # Create a label to display the status of the sniffer
        self.status_label = QLabel("Sniffer not running", self)
        self.status_label.move(150, 100)

        self.name_label = QLabel("Batuhan Aydin", self)
        self.name_label.move(220, 160)

    def start_sniffer(self):
        try:
            sniff(filter="tcp or udp or icmp or tcp port 80 or tcp port 443 tcp port 21", prn=self.packet_handlers, store=0)
            self.status_label.setText("Sniffer stopped")
        except Scapy_Exception as e:
            self.status_label.setText("Scapy Error occurred: Make sure scapy is properly installed on your computer")
        except socket.error as se:
            if 'tcp' in se.strerror.lower():
                self.status_label.setText("TCP Socket Error occurred")
            elif 'udp' in se.strerror.lower():
                self.status_label.setText("UDP Socket Error occurred")
        except Exception as e:
            self.status_label.setText("Error Occured")

    def packet_handlers(self, packet):
        if packet.haslayer(TCP):
            packet_handler_TCP(packet)
        elif packet.haslayer(UDP):
            packet_handeler_UDP(packet)
        elif packet.haslayer(ICMP):
            packet_handler_ICMP(packet)
        elif packet.haslayer(Raw) and packet[TCP].dport and packet.haslayer(TCP) == 80:
            packet_handler_HTTP(packet)
        elif packet.haslayer(Raw) and packet[TCP].dport and packet.haslayer(TCP) == 443:
            packet_handler_HTTPS(packet)
        elif packet.haslayer(Raw) and packet.haslayer(TCP) and packet[TCP].dport == 21:
            packet_handler_FTP(packet)

if __name__ == '__main__':
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()