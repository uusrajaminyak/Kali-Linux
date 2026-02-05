import pefile
import sys
from unicorn import *
from unicorn.x86_const import *
from capstone import *
import string
import re

stack_size = 2 * 1024 * 1024
stack_base = 0x00100000
heap_base = 0x30000000

md = Cs(CS_ARCH_X86, CS_MODE_64)
extracted_strings = set()

def align_page(n):
    alignment = 4096
    return (n + alignment - 1) & ~(alignment - 1)

def is_readable(data):
    if len(data) < 4:
        return False
    try:
        s = data.decode('utf-8')
        return all(c in string.printable for c in s)
    except:
        return False

def hook_mem_invalid(uc, access, address, size, value, user_data):
    start_addr = address & ~0xFFF
    try:
        uc.mem_map(start_addr, 4096)
        if access == UC_MEM_FETCH_UNMAPPED:
            uc.mem_write(address, b'\xc3')
        return True
    except:
        return False
    
def hook_code_monitor(uc, address, size, user_data):
    try:
        code = uc.mem_read(address, size)
        instr = next(md.disasm(code, address))
        regs = [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RDI]
        for reg in regs:
            val = uc.reg_read(reg)
            if val > 0x10000 and val < 0xFFFFFFFFFF:
                try:
                    mem_data = uc.mem_read(val, 64)
                    if b'\x00' in mem_data:
                        mem_data = mem_data.split(b'\x00')[0]
                    if is_readable(mem_data):
                        s = mem_data.decode('utf-8')
                        s = s.strip()
                        if s not in extracted_strings:
                            print(f"[+] Found string at 0x{val:X}")
                            extracted_strings.add(s)
                except:
                    pass
    except:
        pass

def emulate(file_path):
    global extracted_strings
    extracted_strings = set()
    print(f"[*] Analyzing {file_path}")
    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(stack_base, stack_size)
        mu.reg_write(UC_X86_REG_RSP, stack_base + stack_size - 8)
        pe = pefile.PE(file_path)
        for section in pe.sections:
            virt_size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            if virt_size == 0:
                continue
            v_addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
            alligned_size = align_page(virt_size)
            try:
                mu.mem_map(v_addr, alligned_size)
            except UcError as e:
                pass
            mu.mem_write(v_addr, section.get_data())
        
        entry_point = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid)
        mu.hook_add(UC_HOOK_CODE, hook_code_monitor)
        print(f"[*] Starting emulation at 0x{entry_point:X}")
        mu.emu_start(entry_point, entry_point + 0x10000, count = 200000)
        print("[*] Emulation complete.")
        
        pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        high_value_strings = []
        other_strings = []
        for s in extracted_strings:
            if len(s) < 5:
                continue
            if pattern.search(s):
                high_value_strings.append(s)
            else:
                other_strings.append(s)
        print(f"[+] High-value IOCs found:")
        if high_value_strings:
            for ioc in high_value_strings:
                print(f"[+] {ioc}")
        else:
            print("[*] No high-value IOCs found.")
            
        print(f"[+] Other extracted strings:")
        other_strings.sort(key=len, reverse=True)
        for s in other_strings[:10]:
            print(f"- {s}")
    except UcError as e:
        print(f"[!] Unicorn error: {e}")
    except Exception as e:
        print(f"[!] Error: {e}")
            

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 ripper.py <target.exe>")
    else:
        emulate(sys.argv[1])