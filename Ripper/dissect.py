import pefile
import sys
import os

def examine_body(file_path):
    print(f"[*] Examining file: {file_path}")
    try:
        pe = pefile.PE(file_path)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        start_address = image_base + entry_point
        print(f"[+] Image Base: 0x{image_base:08x}")
        print(f"[+] Entry Point: 0x{entry_point:08x}")
        print(f"[+] Start Address: 0x{start_address:08x}")
        print(f"\n[+] Sections:")
        print(f"{'Name':<10} {'Virtual Address':<18} {'Virtual Size':<15} {'Raw Size':<10} {'Characteristics':<20}")
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00') 
            vaddr = section.VirtualAddress
            vsize = section.Misc_VirtualSize
            raw_size = section.SizeOfRawData
            characteristics = section.Characteristics
            print(f"{name:<10} 0x{vaddr:08x}     0x{vsize:08x}    0x{raw_size:08x}   0x{characteristics:08x}")
    except pefile.PEFormatError as e:
        print(f"[!] PEFormatError: {e}")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 dissect.py <target.exe>")
    else:
        examine_body(sys.argv[1])