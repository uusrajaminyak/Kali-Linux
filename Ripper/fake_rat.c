#include <stdio.h>
#include <string.h>
#include <windows.h>

char encrypted_config[] = {
    0x70, 0x78, 0x73, 0x6f, 0x70, 0x77, 0x79, 0x6f, 
    0x70, 0x6f, 0x70, 0x71, 0x71, 0x00 
};

void decrypt_config(char* data, char key) {
    int i = 0;
    while(data[i] != 0x00) {
        data[i] = data[i] ^ key;
        i++;
    }
}

int main() {
    decrypt_config(encrypted_config, 'A');
    printf("Decrypted Config: %s\n", encrypted_config);
    Sleep(100);
    return 0;
}