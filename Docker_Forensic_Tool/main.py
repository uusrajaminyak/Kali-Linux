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

def dump_memory(host_pid, container_name):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{timestamp}_{container_name}_memory.dump"
    output_path = os.path.join(Evidence_Dir, filename)
    print(f"Begin memory dump for pid {host_pid}")
    try:
        cmd = ["gcore", "-o", output_path, str(host_pid)]
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        generated_file = f"{output_path}.{host_pid}"
        if os.path.exists(generated_file):
            final_path = output_path
            os.rename(generated_file, final_path)
            print(f"Memory dump saved to {final_path}")
            file_hash = calculate_sha256(final_path)
            print(f"SHA256: {file_hash}")
            with open(os.path.join(Evidence_Dir, "audit_log.txt"), "a") as log:
                log.write(f"{timestamp} | memory_dump | {final_path} | {file_hash}\n")
        else:
            print("Memory dump file was not created.")
    except FileNotFoundError:
        print("gcore command not found. Please install gdb package.")
    except subprocess.CalledProcessError as e:
        print(f"Error during memory dump: {e}")
    except Exception as e:
        print(f"Unexpected error during memory dump: {e}")

def clean_evidence():
    folder = Evidence_Dir
    print(f"Cleaning evidence folder: {folder}")
    confirm = input("Are you sure you want to delete all collected evidence? (y/n): ")
    if confirm.lower() != 'y':
        print("Aborting cleanup.")
        return
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
                print(f"Deleted file: {file_path}")
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f"Failed to delete {file_path}. Reason: {e}")

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--clean":
        clean_evidence()
        sys.exit(0)

    if len(sys.argv) < 3:
        print("Commands:")
        print(" 1. Collect File : sudo python3 main.py [container_name] [file_path]")
        print(" 2. Dump Memory  : sudo python3 main.py [container_name] --memory")
        print(" 3. Clean Evidence Folder : sudo python3 main.py --clean")
        sys.exit(1)

    container_name = sys.argv[1]
    second_arg = sys.argv[2]

    print(f"===== CONTAINER FORENSIC TOOL =====")
    pid = get_container_pid(container_name)
    print(f"[+] Target Container: {container_name}")
    print(f"[+] Host PID: {pid}")

    if second_arg == "--memory":
        dump_memory(pid, container_name)
    else:
        collect_file(pid, second_arg)