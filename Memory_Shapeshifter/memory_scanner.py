import sys
import os
import re

def read_memory(pid):
    mem_file = f"/proc/{pid}/mem"
    maps_file = f"/proc/{pid}/maps"
    Target_Signature = b"HACKED!"
    if not os.path.exists(mem_file) or not os.path.exists(maps_file):
        print("[-] Process does not exist")
        return
    print(f"[+] Reading memory of PID: {pid}")
    found = False
    try:
        with open(maps_file, 'r') as map_f:
            with open(mem_file, 'rb', 0) as mem_f:
                for line in map_f:
                    parts = line.split()
                    if 'r' not in parts[1]: continue
                    start = int(parts[0].split('-')[0], 16) 
                    end = int(parts[0].split('-')[1], 16)
                    try:
                        mem_f.seek(start)
                        chunk = mem_f.read(end-start)
                        if Target_Signature in chunk:
                            print(f"[+] Found malware signature in: 0x{start:x}")
                            print(f"[+] Permission: {parts[1]}")
                            print(f"[+] Signature: {Target_Signature}")
                            found = True;
                            break
                    except:
                        continue
    except PermissionError:
        print("[-] Permission denied. Try running as root.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")
    if not found:
        print("[-] No malware signature found in memory.")
    else:
        print("[+] Scan complete.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: sudo python3 memory_scanner.py <pid>")
        sys.exit()
    read_memory(sys.argv[1])