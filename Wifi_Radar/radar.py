from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt
import os
import time
from threading import Thread

INTERFACE = "wlan0mon"
ap_list = []

def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        try:
            bssid = pkt[Dot11].addr2
        except:
            return
        try:
            ssid = pkt[Dot11Elt].info.decode()
        except:
            ssid = "<Hidden/Error>"
            
        try:
            dbm_signal = pkt.dbm_AntSignal
        except:
            dbm_signal = "N/A"
        if bssid not in ap_list:
            ap_list.append(bssid)
            print(f"Found: {ssid:<20} | MAC: {bssid} | PWR: {dbm_signal} dBm")

def start_sniffer():
    print(f"[*] Radar active on {INTERFACE}")
    print(f"{'Wifi':<20} | {'MAC':<17} | Signal")
    print("-" * 50)
    try:
        sniff(iface=INTERFACE, prn=packet_handler, store=0)
    except Exception as e:
        print(f"Error: {e}")

def channel_hopper():
    while True:
        try:
            for channel in range(1, 14):
                os.system(f"iw dev {INTERFACE} set channel {channel}")
                time.sleep(0.5)
        except KeyboardInterrupt:
            break
        except Exception as e:
            continue

if __name__ == "__main__":
    hopper = Thread(target=channel_hopper)
    hopper.daemon = True
    hopper.start()
    start_sniffer()