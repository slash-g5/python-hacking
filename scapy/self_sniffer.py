from scapy.all import sniff
from scapy.layers.inet import TCP, IP
from scapy.utils import wrpcap


def packet_callback(packet):
    if TCP in packet and IP in packet:
        if packet[TCP].dport in [25, 587, 465]:
            print("[*] Destination: {}".format(packet[IP].dst))
            print("[*] Source: {}".format(packet[IP].src))
            print("[*] Protocol: TCP")
            print("[*] Destination Port: {}".format(packet[TCP].dport))
            print("[*] Source Port: {}".format(packet[TCP].sport))
            print("[*] ")
            print("\n")


def main():
    packets = sniff(filter='port 80', count=20, iface='wlo1')
    wrpcap('arper.pcap', packets)


if __name__ == "__main__":
    main()
