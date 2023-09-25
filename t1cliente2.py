from scapy.all import *
import threading

class RawClient:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, interface="Ethernet"):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.interface = interface

    def send_message(self, message):
        # Construct the packet using Scapy
        packet = Ether(src=self.src_mac, dst=self.dst_mac) / \
                 IP(src=self.src_ip, dst=self.dst_ip) / \
                 UDP(sport=self.src_port, dport=self.dst_port) / \
                 message
        sendp(packet, iface=self.interface)
        print(f"Sent message: {message}")

    def listen_for_messages(self):
        filter_str = f"udp and src host {self.dst_ip} and src port {self.dst_port} and dst port {self.src_port}"
        sniff(filter=filter_str, prn=self._handle_packet, iface=self.interface)

    def _handle_packet(self, packet):
        if packet[UDP].dport == self.src_port:
            print(f"Received message: {packet[Raw].load.decode()}")

    def start(self):
        listener_thread = threading.Thread(target=self.listen_for_messages)
        listener_thread.start()

        while True:
            message = input("Enter message to send (or 'exit' to quit): ")
            if message == 'exit':
                break
            self.send_message(message)

if __name__ == "__main__":
    client = RawClient(src_ip="192.168.1.5", dst_ip="192.168.1.7", src_port=54321, dst_port=12345, src_mac="00:D7:6D:1A:5C:39", dst_mac="10:62:EB:2E:06:18", interface="Wi-Fi")
    client.start()
