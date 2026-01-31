#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint8_t bytecode[] = {
    0x10, 0x00,
    0x20, 0x05,
    0x40, 0x2D,
    0xFF
};

int vm_cpu(int input) {
    int pc = 0;
    int reg_acc = 0;
    int running = 1;

    while (running) {
        uint8_t opcode = bytecode[pc];
        pc++;

        switch (opcode) {
            case 0x10:
                reg_acc = input;
                pc++;
                break;
            case 0x20:
                reg_acc += bytecode[pc];
                pc++;
                break;
            case 0x30:
                reg_acc -= bytecode[pc];
                pc++;
                break;
            case 0x40:
                reg_acc ^= bytecode[pc];
                pc++;
                break;
            case 0xFF:
                running = 0;
                break;
            default:
                running = 0;
                break;
        }
    }
    return reg_acc;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <input_value>\n", argv[0]);
        return 1;
    }

    int input = atoi(argv[1]);
    int result = vm_cpu(input);
    printf("Result: %d\n", result);
    return 0;
}