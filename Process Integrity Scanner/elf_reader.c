#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <elf.h>

int main(int argc, char *argv[]){
    if (argc != 2) {
        printf("Usage: %s <path_to_binary>\n", argv[0]);
        return 1;
    }
    const char *filepath = argv[1];
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        perror("Failed to open file");
        return 1;
    }

    Elf64_Ehdr header;
    if (fread(&header, 1, sizeof(header), file) != sizeof(header)) {
        fprintf(stderr, "Not a valid ELF file or read error\n");
        fclose(file);
        return 1;
    }

    if (header.e_ident[EI_MAG0] != ELFMAG0 ||
        header.e_ident[EI_MAG1] != ELFMAG1 ||
        header.e_ident[EI_MAG2] != ELFMAG2 ||
        header.e_ident[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "Not a valid ELF file\n");
        fclose(file);
        return 1;
    }
    
    fseek(file, header.e_phoff, SEEK_SET);

    printf("Valid ELF file detected.\n");
    printf("Entry point: 0x%lx\n", header.e_entry);
    printf("Header Offset Program: %ld", header.e_phoff);

    for (int i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr phdr;
        fread(&phdr, 1, sizeof(phdr), file);
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            printf("Found executable\n");
            printf("Offset in file: 0xlx\n", phdr.p_offset);
            printf("Virtual Address: 0x%lx\n", phdr.p_vaddr);
            printf("Size in file: 0x%lx\n", phdr.p_filesz);
            printf("Size in memory: 0x%lx\n", phdr.p_memsz);
        }
    }
    fclose(file);
    return 0;
}