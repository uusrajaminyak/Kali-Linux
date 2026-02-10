import os
import sys
import ctypes
from ctypes import c_int, c_ulong, c_char, c_void_p, c_long, Structure

sys_getdents64 = 217
dt_reg = 8

class LinuxDirent64(Structure):
    _fields_ = [
        ("d_ino", c_ulong),
        ("d_off", c_long),
        ("d_reclen", ctypes.c_ushort),
        ("d_type", c_char),
        ("d_name", c_char * 256)
    ]
    
def get_kernel_view(path="."):
    kernel_files = set()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as e:
        print(f"Error opening directory {path}: {e}")
        return set()
    
    buff_size = 1024 * 1024
    buffer = ctypes.create_string_buffer(buff_size)
    libc = ctypes.CDLL(None)
    
    while True:
        nread = libc.syscall(sys_getdents64, c_int(fd), buffer, c_int(buff_size))
        if nread == -1:
            break
        if nread == 0:
            break
        
        index = 0
        while index < nread:
            struct_ptr = ctypes.cast(ctypes.byref(buffer, index), ctypes.POINTER(LinuxDirent64))
            dirent = struct_ptr.contents
            name = dirent.d_name.decode('utf-8', errors='ignore')
            if name not in ('.', '..'):
                kernel_files.add(name)
            index += dirent.d_reclen
    os.close(fd)
    return kernel_files

def get_user_view(path="."):
    try:
        files = os.listdir(path)
        return set(files)
    except OSError:
        return set()
    
def main():
    print("===CROSS-VIEW FILE SYSTEM DETECTOR===")
    target_dir = "."
    print(f"Scanning directory: {os.path.abspath(target_dir)}")
    print("Getting User-Mode View...")
    user_files = get_user_view(target_dir)
    print(f"Found: {len(user_files)} files")
    print("Getting Kernel-Mode View...")
    kernel_files = get_kernel_view(target_dir)
    print(f"Found: {len(kernel_files)} files")
    print("Comparing views...")
    hidden_files = kernel_files - user_files
    if hidden_files:
        print("Potentially hidden files detected:")
        for f in hidden_files:
            print(f" - {f}")
        print("LD_PRELOAD-based rootkit may be present.")
    else:
        print("No discrepancies found. No LD_PRELOAD-based rootkit detected.")
        
if __name__ == "__main__":
    main()