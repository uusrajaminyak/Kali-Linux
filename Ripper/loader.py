import pefile
from unicorn import *
from unicorn.x86_const import *
import sys

Max_mem = 100 * 1024 * 1024
stack_size = 2 * 1024 * 1024
stack_base = 0x00100000

def align_page(n):
    alignment = 4096
    return (n + alignment - 1) & ~(alignment - 1)

def load(file_path):
    print(f"[*] Loading barrier for: {file_path}")
    try:
        pe = pefile.PE(file_path)
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        print("[+] Unicorn engine initialized.")
        mu.mem_map(stack_base, stack_size)
        mu.reg_write(UC_X86_REG_RSP, stack_base + stack_size - 8)
        print(f"[+] Stack mapped and initialized at 0x{stack_base:08x}")
        total_mapped = 0
        for section in pe.sections:
            if section.SizeOfRawData == 0:
                continue
            v_addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
            raw_size = section.SizeOfRawData
            aligned_size = align_page(raw_size)
            total_mapped += aligned_size
            if total_mapped > Max_mem:
                print("[-] Exceeded maximum memory limit.")
                raise Exception("Memory limit exceeded")
            try:
                mu.mem_map(v_addr, aligned_size)
            except UcError as e:
                print(f"[-] Memory write error at 0x{v_addr:08x}: {e}")
                pass
            mu.mem_write(v_addr, section.get_data())
        entry_point = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        print(f"[+] Entry point set to 0x{entry_point:x}")
        opcode = mu.mem_read(entry_point, 10)
        print(f"[+] Verification memory: {opcode.hex()}")
        return mu, entry_point
    except Exception as e:
        print(f"[-] Error loading PE file: {e}")
        return None, None
    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 loader.py <target.exe>")
    else:
        mu, ep = load(sys.argv[1])
        if mu:
            print("[+] Success, malware loaded into Unicorn.")
