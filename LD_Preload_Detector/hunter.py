import os
import sys

known_ld_preload_lib = ["evil_kit.so"]

def check_env():
    print("[*] checking environment variables...")
    preload_var = os.environ.get('LD_PRELOAD')
    if preload_var:
        print(f"[!] LD_PRELOAD detected,value: {preload_var}")
        
        for evil in known_ld_preload_lib:
            if evil in preload_var:
                print(f"[!] Known malicious library detected: {evil}")
                return True
    else:
        print("[*] No LD_PRELOAD environment variable set.")
    return False

def check_mem():
    print("[*] checking memory map")
    try:
        with open("/proc/self/maps", "r") as f:
            map_content = f.read()
            
        found = False
        for line in map_content.splitlines():
            for evil in known_ld_preload_lib:
                if evil in line:
                    print(f"[!] Known malicious library found in memory map: {line.strip()}")
                    found = True
        if not found:
            print("[*] No known malicious libraries found in memory map.")
    except Exception as e:
        print(f"[!] Error reading memory map: {e}")
        
def main():
    print("===Rootkit Hunter===")
    infected = check_env()
    check_mem()
    
    if infected:
        print("[!] System may be compromised!")
    else:
        print("[*] No signs of compromise detected.")

if __name__ == "__main__":
    main()