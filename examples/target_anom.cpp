#include <windows.h>
#include <cstdio>
#include <cstring>

int wmain(){
    // allocate RWX and place a minimal 'MZ'...'PE' signature to simulate hollowing.
    void* p = VirtualAlloc(NULL, 0x2000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    unsigned char* b = (unsigned char*)p;
    if (b){
        memset(b, 0, 0x2000);
        b[0] = 'M'; b[1] = 'Z';
        // e_lfanew at 0x3C: set to 0x80
        *(int*)&b[0x3C] = 0x80;
        b[0x80] = 'P'; b[0x81] = 'E'; b[0x82] = 0; b[0x83] = 0;
    }
    wprintf(L"target_anom ready, pid=%lu\n", GetCurrentProcessId());
    Sleep(500); // give scanner some time
    return 0;
}
