import os
import sys
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

def run_nmap(target_ip):
    print(f"scanning {target_ip}")
    output_file = "result.xml"
    command = f"nmap -sV -p- --min-rate 1000 -oX {output_file} {target_ip}"
    try:
        subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[+] scan finished,analyzing result...")
        return output_file
    except subprocess.CalledProcessError:
        print("[!] Nmap error")
        sys.exit
    except KeyboardInterrupt:
        print("[!] Aborted")
        sys.exit

def parse_and_search(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    found_vuln = 0
    print(f"{'PORT':<8} | {'SERVICE':<20} | {'VERSION':<20} | {'EXPLOIT STATUS'}")

    for host in root.findall('host'):
        for port in host.findall('.//port'):
            port_id = port.get('portid')
            state = port.find('state').get('state')
            if state == 'open':
                service = port.find('service')
                if service is not None:
                    product = service.get('product') or "Unknown"
                    version = service.get('version') or ""
                    query = f"{product} {version}".strip()
                    if query and query != "Unknown":
                        exploit_check = subprocess.run(
                            f"searchsploit '{query}",
                            shell=True,
                            capture_output=True,
                            text=True
                        )
                        if "Exploit Title" in exploit_check.stdout:
                            status = "Potential Exploit Found!"
                            found_vuln += 1
                            save_log(port_id, query, exploit_check.stdout)
                        else:
                            status = "Clean"
                    else:
                        status = "No Version Detected"
                    print(f"{port_id:<8} | {product[:20]:<20} | {version[:20]:<20} | {status}")
    if found_vuln > 0:
        print(f"[!] Founded {found_vuln} vulnerable(s)")
    else:
        print("Target is clean")

def save_log(port, software, output):
    with open("rsniper_result.txt", "a") as f:
        f.write(f"\n{'='*50}\n")
        f.write(f"Target Port: {port} | Software: {software}\n")
        f.write(f"{'='*50}\n")
        f.write(output)

if __name__ == "__main__":
    os.system("clear")
    if len(sys.argv) != 2:
        print(f"useage: sudo python3 sniper.py <Target_IP>")
        sys.exit()
    target = sys.argv[1]
    if os.path.exists("sniper_result.txt"):
        os.remove("sniper_result.txt")
    xml_out = run_nmap(target)
    parse_and_search(xml_out)
    if os.path.exists(xml_out):
        os.remove(xml_out)