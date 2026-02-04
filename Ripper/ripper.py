import pefile
import sys
from unicorn import *
from unicorn.x86_const import *
from capstone import *

stack_size = 2 * 1024 * 1024
stack_base = 0x00100000

md = Cs(CS_ARCH_X86, CS_MODE_64)

def align_page(n):
    alignment = 4096
    return (n + alignment - 1) & ~(alignment - 1)

def hook_mem_invalid(uc, access, address, size, value, user_data):
    start_addr = address & ~0xFFF
    try:
        uc.mem_map(start_addr, 4096)
        return True
    except:
        return False
    
def hook_code_monitor(uc, address, size, user_data):
    try:
        code = uc.mem_read(address, size)
        instr = next(md.disasm(code, address))
        print(f"ripper: 0x{address:x} | {instr.mnemonic:<6} {instr.op_str}")
    except StopIteration:
        print(f"ripper: 0x{address:x} | ???")
    except:
        pass

def emulate(file_path):
    print(f"[*] Analyzing: {file_path}")
    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        print(f"[*] ID: {id(mu)}")
        mu.mem_map(stack_base, stack_size)
        mu.reg_write(UC_X86_REG_RSP, stack_base + stack_size - 8)
        pe = pefile.PE(file_path)
        for section in pe.sections:
            if section.SizeOfRawData == 0:
                continue
            v_addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
            aligned_size = align_page(section.SizeOfRawData)
            try:
                mu.mem_map(v_addr, aligned_size)
            except UcError as e:
                pass
            mu.mem_write(v_addr, section.get_data())
        entry_point = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
        mu.hook_add(UC_HOOK_CODE, hook_code_monitor)
        print("[+] Starting emulation...")
        mu.emu_start(entry_point, entry_point + 0x100000, count=50)
        print("[+] Emulation complete.")
    except Exception as e:
        print(f"[-] Error during emulation: {e}")
    except UcError as e:
        print(f"[-] Unicorn error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 ripper.py <target.exe>")
    else:
        emulate(sys.argv[1])