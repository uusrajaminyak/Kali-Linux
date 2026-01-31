#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>

unsigned long get_base_address(int pid, const char *filename) {
    char maps_path[256];
    char line[512];
    FILE *file;
    unsigned long start_addr = 0;

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    file = fopen(maps_path, "r");
    if (!file) {
        perror("Failed to open maps file");
        return 0;
    }

    while(fgets(line, sizeof(line), file)) {
        if (strstr(line, filename)) {
            sscanf(line, "%lx-", &start_addr);
            break;
        }
    }
    fclose(file);
    return start_addr;
}

void print_diff(unsigned char *disk, unsigned char *mem, int size) {
    printf("\nForensic Dump:\n");
    printf("DISK(original):");
    for (int i = 0;i < 16 && i < size;i++) {
        printf(" %02x", disk[i]);
    }
    printf("\n");
    printf("MEMORY(modified):");
    for (int i = 0;i < 16 && i < size;i++) {
        if (disk[i] != mem[i]) {
            printf("\033[1;31m %02x\033[0m", mem[i]);
        } else {
            printf(" %02x", mem[i]);
        }
    }
    printf("\n\n");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <pid> <path_to_binary>\n", argv[0]);
        return 1;
    }
    
    int pid = atoi(argv[1]);
    const char *filepath = argv[2];

    printf("PID: %d\n", pid);
    printf("Binary Path: %s\n", filepath);

    unsigned long base_addr = get_base_address(pid, filepath);
    if (base_addr == 0) {
        printf("Failed to find base address for PID %d and binary %s\n", pid, filepath);
        return 1;
    } else {
        printf("Base Address: 0x%lx\n", base_addr);
    }

    FILE *f_disk = fopen(filepath, "rb");
    if (!f_disk) {
        perror("Failed to disk");
        return 1;
    }

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), f_disk) != sizeof(ehdr)) {
        printf("Not a valid ELF file or read error\n");
        fclose(f_disk);
        return 1;
    }

    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    FILE *f_mem = fopen(mem_path, "rb");
    if (!f_mem) {
        perror("Failed to open mem");
        fclose(f_disk);
        return 1;
    }

    fseek(f_disk, ehdr.e_phoff, SEEK_SET);
    int sus_count = 0;
    for (int i = 0;i < ehdr.e_phnum;i++) {
        Elf64_Phdr phdr;
        fread(&phdr, 1, sizeof(phdr), f_disk);
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            long size = phdr.p_filesz;
            unsigned long disk_offset = phdr.p_offset;
            unsigned long mem_offset = base_addr + phdr.p_vaddr;
            printf("Checking segment @ 0x%lx\n", mem_offset, size);
            char *buf_disk = malloc(size);
            char *buf_mem = malloc(size);
            long cur_pos = ftell(f_disk);
            fseek(f_disk, disk_offset, SEEK_SET);
            fread(buf_disk, 1, size, f_disk);
            fseek(f_disk, cur_pos, SEEK_SET);
            fseek(f_mem, mem_offset, SEEK_SET);
            fread(buf_mem, 1, size, f_mem);
            if (memcmp(buf_disk, buf_mem, size) == 0) {
                printf("Segment OK\n");
            } else {
                printf("Segment MODIFIED! Injection?\n");
                print_diff((unsigned char *)buf_disk, (unsigned char *)buf_mem, size);
                sus_count++;
            }
            free(buf_disk);
            free(buf_mem);
        }
    }
    fclose(f_disk);
    fclose(f_mem);
    if (sus_count == 0) {
        printf("No modifications detected.\n");
    } else {
        printf("Total modified segments: %d\n", sus_count);
    }

    return 0;
}