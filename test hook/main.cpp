#include <windows.h>
#include <tlhelp32.h> 
#include <iostream>
#include <vector>



DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {

            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pid;
}

int main() {

    const wchar_t* targetProcess = L"main.exe";

    std::wcout << "[*] Looking for " << targetProcess << "...\n";

    DWORD pid = GetProcessIdByName(targetProcess);

    if (pid == 0) {
        std::wcout << "[-] Process " << targetProcess << " not found! Is it running?\n";
        system("pause");
        return 1;
    }

    std::wcout << "[+] Found " << targetProcess << " with PID: " << pid << "\n";


    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] Failed to open process. Error: " << GetLastError() << "\n";
        system("pause");
        return 1;
    }


    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    std::vector<const char*> targets = {
         "NtWriteVirtualMemory",
         "NtCreateThreadEx", "NtOpenProcess",
        "NtQueryInformationProcess", "NtMapViewOfSection", "NtUnmapViewOfSection", "NtResumeThread"
    };

    BYTE hookOpcode = 0xE9; 

    std::cout << "\n[*] Injecting 0xE9 hooks into PID " << pid << "...\n";

    for (const char* name : targets) {
        FARPROC addr = GetProcAddress(hNtdll, name);
        if (addr) {
            SIZE_T bytesWritten = 0;

            if (WriteProcessMemory(hProcess, (LPVOID)addr, &hookOpcode, sizeof(hookOpcode), &bytesWritten)) {
                std::cout << "[+] Hooked: " << name << " at 0x" << (void*)addr << "\n";
            }
            else {
                std::cout << "[-] Failed to write to " << name << "\n";
            }
        }
    }

    CloseHandle(hProcess);
    std::cout << "\n[*] Done! Now let your Zig scanner run.\n";
    system("pause");
    return 0;
}