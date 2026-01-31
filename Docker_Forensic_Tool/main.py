import subprocess
import os
import json
import sys
import shutil
import hashlib
import datetime

Evidence_Dir = "collected_evidence"
if not os.path.exists(Evidence_Dir):
    os.makedirs(Evidence_Dir)

def get_container_pid(container_name):
    try:
        cmd = ["docker", "inspect", container_name]
        result = subprocess.check_output(cmd)
        data = json.loads(result)
        host_pid = data[0]['State']['Pid']
        return host_pid
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving PID for container {container_name}: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

def check_proc_process(pid):
    proc_path = f"/proc/{pid}/root"
    if os.path.exists(proc_path):
        try:
            contents = os.listdir(proc_path)
            print(f"Success! Seeing {len(contents)} items in {proc_path}")
            return True
        except PermissionError:
            print(f"Permission denied when accessing {proc_path}. Try running as root.")
            return False
    else:
        print(f"Path {proc_path} does not exist.")
        return False
    
def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating SHA256 for {filepath}: {e}")
        return None
    
def collect_file(host_pid, target_filepath):
    source_path = f"/proc/{host_pid}/root{target_filepath}"
    filename = os.path.basename(target_filepath)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dest_path = os.path.join(Evidence_Dir, f"{filename}_{host_pid}_{timestamp}")
    print(f"Collecting file from {target_filepath}")
    if not os.path.exists(source_path):
        print(f"Source file {target_filepath} does not exist.")
        return
    try:
        shutil.copy2(source_path, dest_path)
        print(f"File copied to {dest_path}")
        file_hash = calculate_sha256(dest_path)
        print(f"SHA256: {file_hash}")
        with open(os.path.join(Evidence_Dir, "audit_log.txt"), "a") as log:
            log.write(f"{timestamp} | {target_filepath} | {dest_path} | {file_hash}\n")
    except PermissionError:
        print(f"Permission denied when accessing {source_path}. Try running as root.")
    except Exception as e:
        print(f"Error collecting file {target_filepath}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sudo python3 main.py <container_name> <file_to_collect>")
        sys.exit(1)
    container_name = sys.argv[1]
    target_files = sys.argv[2]
    print(f"Target container: {container_name}")
    pid = get_container_pid(container_name)
    print(f"Container PID on host: {pid}")
    collect_file(pid, target_files)