#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, filename)) {
            sscanf(line, "%lx-", &start_addr);
            break;
        }
    }
    fclose(file);
    return start_addr;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <pid> <path_to_binary>\n", argv[0]);
        printf("Example: %s 1234 /usr/bin/bash\n", argv[0]);
        return 1;
    }
    
    int pid = atoi(argv[1]);
    const char *filepath = argv[2];

    printf("PID: %d\n", pid);
    printf("Binary Path: %s\n", filepath);

    unsigned long base_adddr = get_base_address(pid, filepath);
    if (base_adddr == 0) {
        printf("Failed to find base address for PID %d and binary %s\n", pid, filepath);
        return 1;
    } else {
        printf("Base Address: 0x%lx\n", base_adddr);
    }

    return 0;
}