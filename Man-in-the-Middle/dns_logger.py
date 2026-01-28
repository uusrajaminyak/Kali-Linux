from scapy.all import *
import sys
from datetime import datetime

TARGET_IP = "..."

def packet_handler(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        if pkt[IP].src == TARGET_IP:
            try:
                website = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                waktu = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if "google" not in website and "gstatic" not in website:
                    print(f"[{waktu}] {TARGET_IP} requested: {website}")
                else:
                    print(f"[{waktu}] android system: {website}")
            except Exception as e:
                pass

if __name__ == "__main__":
    print(f"[*] Starting DNS logger for target IP: {TARGET_IP}")
    sniff(filter=f"udp port 53 and ip src {TARGET_IP}", prn=packet_handler, store=0)