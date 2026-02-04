import pefile
from unicorn import *
from unicorn.x86_const import *
import sys
from capstone import *

heap_base = 0x30000000
stack_size = 2 * 1024 * 1024
stack_base = 0x00100000

md = Cs(CS_ARCH_X86, CS_MODE_64)

def align_page(n):
    alignment = 4096
    return (n + alignment - 1) & ~(alignment - 1)

def hook_code(uc, address, size, user_data):
    try:
        code = uc.mem_read(address, size)
        instr = next(md.disasm(code, address))
        print(f"tracer: 0x{address:x} | {instr.mnemonic:<6} {instr.op_str}")
    except StopIteration:
        print(f"tracer: 0x{address:x} | ???")

def hook_mem_invalid(uc, access, address, size, value, user_data):
    start_addr = address & ~0xFFF
    map_size = 4096
    print(f"[+] Malware tried to access unmapped memory at 0x{address:x}")
    print(f"[+] Mapping memory at 0x{start_addr:x} of size {map_size} bytes")
    try:
        uc.mem_map(start_addr, map_size)
        return True
    except UcError as e:
        print(f"[-] Failed to map memory at 0x{start_addr:x}: {e}")
        return False

def load_and_trace(file_path):
    print(f"[*] Tracing: {file_path}")
    try:
        pe = pefile.PE(file_path)
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(stack_base, stack_size)
        mu.reg_write(UC_X86_REG_RSP, stack_base + stack_size - 8)

        for section in pe.sections:
            if section.SizeOfRawData == 0:
                continue
            v_addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
            aligned_size = align_page(section.SizeOfRawData)
            try:
                mu.mem_map(v_addr, aligned_size)
            except UcError as e:
                pass
            print(f"[+] writting sections... at 0x{v_addr:08x}")
            mu.mem_write(v_addr, section.get_data())

        entry_point = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        print(f"[+] Entry point at 0x{entry_point:x}")
        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
        print("[*] Starting emulation...")
        mu.emu_start(entry_point, entry_point + 0x10000, count=50)
        print("[*] Emulation complete.")
    except UcError as e:
        print(f"[-] Unicorn error: {e}")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 tracer.py <target.exe>")
    else:
        load_and_trace(sys.argv[1])