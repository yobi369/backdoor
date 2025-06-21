#include <windows.h>
#include <fstream> // For file logging
#include <string>  // For std::to_string
#include <iomanip> // For std::hex for logging addresses

// Global log file stream
std::ofstream logFile;

// Target API: Beep from kernel32.dll
// BOOL Beep(DWORD dwFreq, DWORD dwDuration);
typedef BOOL (WINAPI* OriginalBeepType)(DWORD dwFreq, DWORD dwDuration);
OriginalBeepType pOriginalBeep = nullptr; // Pointer to the original Beep function address

// Our detour function for Beep
BOOL WINAPI DetourBeep(DWORD dwFreq, DWORD dwDuration) {
    if (logFile.is_open()) {
        logFile << "DetourBeep called! Freq: " << dwFreq << ", Duration: " << dwDuration << std::endl;
    }
    // For this initial version, we do not call the original Beep function.
    // If we wanted to call it (once trampoline is implemented):
    // return pOriginalBeep(dwFreq, dwDuration);
    return TRUE; // Pretend it succeeded
}

// Function prototypes for hooking logic
void InstallHook();
void UninstallHook();

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Open log file in append mode. Using a fixed path for simplicity.
        // Ensure this path is writable by the target process.
        // Using C:\ might require admin rights for the target process.
        // Consider using a path in %TEMP% or user's appdata for better compatibility.
        logFile.open("C:\\hook_log.txt", std::ios_base::app);
        if (logFile.is_open()) {
            logFile << "hook_dll.dll injected into PID: " << GetCurrentProcessId() << std::endl;
        }
        InstallHook(); // Call to install hooks
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        UninstallHook(); // Call to uninstall hooks
        if (logFile.is_open()) {
            logFile << "hook_dll.dll detaching from PID: " << GetCurrentProcessId() << std::endl;
            logFile.close();
        }
        break;
    }
    return TRUE;
}

// Store original bytes for unhooking
const int HOOK_SIZE = 14; // Size of our JMP instruction for x64: FF 25 00000000 <64-bit address>
unsigned char originalBeepBytes[HOOK_SIZE];
bool hookInstalled = false;

void InstallHook() {
    if (logFile.is_open()) {
        logFile << "Attempting to install hook on Beep..." << std::endl;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        if (logFile.is_open()) logFile << "Failed to get handle for kernel32.dll. Error: " << GetLastError() << std::endl;
        return;
    }

    pOriginalBeep = (OriginalBeepType)GetProcAddress(hKernel32, "Beep");
    if (pOriginalBeep == NULL) {
        if (logFile.is_open()) logFile << "Failed to get address for Beep. Error: " << GetLastError() << std::endl;
        return;
    }

    if (logFile.is_open()) {
        logFile << "Original Beep address: 0x" << std::hex << (uintptr_t)pOriginalBeep << std::dec << std::endl;
        logFile << "DetourBeep address: 0x" << std::hex << (uintptr_t)&DetourBeep << std::dec << std::endl;
    }

    // Construct the JMP instruction: FF 25 00 00 00 00 [absolute 64-bit address of DetourBeep]
    // This is JMP QWORD PTR [RIP+0x0], followed by the address.
    // The assembler effectively puts the address data immediately after the instruction.
    unsigned char jmpInstruction[HOOK_SIZE];
    jmpInstruction[0] = 0xFF; // JMP
    jmpInstruction[1] = 0x25; // QWORD PTR [RIP+0]
    jmpInstruction[2] = 0x00; // Relative offset from RIP is 0, meaning the address is at RIP+6
    jmpInstruction[3] = 0x00;
    jmpInstruction[4] = 0x00;
    jmpInstruction[5] = 0x00;

    uintptr_t detourAddress = (uintptr_t)&DetourBeep;
    memcpy(&jmpInstruction[6], &detourAddress, sizeof(detourAddress)); // Copy the 8-byte address

    if (logFile.is_open()) {
        logFile << "JMP instruction bytes to write: ";
        for(int i=0; i < HOOK_SIZE; ++i) logFile << std::hex << std::setw(2) << std::setfill('0') << (int)jmpInstruction[i] << " ";
        logFile << std::dec << std::endl;
    }

    DWORD oldProtect;
    // Change memory protection of the target function's prologue to allow writing
    if (!VirtualProtect((LPVOID)pOriginalBeep, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        if (logFile.is_open()) logFile << "Failed to change memory protection for Beep (VirtualProtect). Error: " << GetLastError() << std::endl;
        return;
    }

    // Save the original bytes from the function prologue before overwriting
    memcpy(originalBeepBytes, (LPVOID)pOriginalBeep, HOOK_SIZE);
    if (logFile.is_open()) {
        logFile << "Original Beep bytes saved: ";
        for(int i=0; i < HOOK_SIZE; ++i) logFile << std::hex << std::setw(2) << std::setfill('0') << (int)originalBeepBytes[i] << " ";
        logFile << std::dec << std::endl;
    }

    // Write the JMP instruction to the target function's prologue
    memcpy((LPVOID)pOriginalBeep, jmpInstruction, HOOK_SIZE);

    // Flush the instruction cache for the modified memory region
    if (!FlushInstructionCache(GetCurrentProcess(), (LPCVOID)pOriginalBeep, HOOK_SIZE)) {
         if (logFile.is_open()) logFile << "Warning: Failed to flush instruction cache. Error: " << GetLastError() << std::endl;
        // This is not always critical but good practice.
    }

    // Restore the original memory protection
    DWORD tempProtect; // VirtualProtect requires a non-null pointer for oldProtect, even if not strictly used in restore.
    if (!VirtualProtect((LPVOID)pOriginalBeep, HOOK_SIZE, oldProtect, &tempProtect)) {
        if (logFile.is_open()) logFile << "Warning: Failed to restore memory protection for Beep. Error: " << GetLastError() << std::endl;
        // The hook is placed, but this is not ideal.
    }

    hookInstalled = true;
    if (logFile.is_open()) logFile << "Beep hook installed successfully." << std::endl;
}

void UninstallHook() {
    if (!hookInstalled || pOriginalBeep == nullptr) { // Check against nullptr explicitly
        if (logFile.is_open()) {
            logFile << "UninstallHook: Hook not installed or pOriginalBeep is null. No action taken." << std::endl;
        }
        return;
    }

    if (logFile.is_open()) {
        logFile << "Attempting to uninstall hook from Beep (address: 0x"
                << std::hex << (uintptr_t)pOriginalBeep << std::dec << ")..." << std::endl;
    }

    DWORD oldProtect;
    // Change memory protection to allow writing back the original bytes
    if (!VirtualProtect((LPVOID)pOriginalBeep, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        if (logFile.is_open()) {
            logFile << "Failed to change memory protection for unhooking Beep (VirtualProtect). Error: " << GetLastError() << std::endl;
        }
        // Still attempt to mark as uninstalled to prevent re-attempts if VirtualProtect is the issue.
        // However, the memory is not restored. This is a problematic state.
        hookInstalled = false;
        return;
    }

    // Restore the original bytes to the function's prologue
    memcpy((LPVOID)pOriginalBeep, originalBeepBytes, HOOK_SIZE);
    if (logFile.is_open()) {
        logFile << "Original Beep bytes restored: ";
        for(int i=0; i < HOOK_SIZE; ++i) logFile << std::hex << std::setw(2) << std::setfill('0') << (int)originalBeepBytes[i] << " ";
        logFile << std::dec << std::endl;
    }

    // Flush the instruction cache
    if (!FlushInstructionCache(GetCurrentProcess(), (LPCVOID)pOriginalBeep, HOOK_SIZE)) {
        if (logFile.is_open()) {
            logFile << "Warning: Failed to flush instruction cache during unhook. Error: " << GetLastError() << std::endl;
        }
    }

    // Restore the original memory protection
    DWORD tempProtect; // Required for the call, not strictly used for the result here.
    if (!VirtualProtect((LPVOID)pOriginalBeep, HOOK_SIZE, oldProtect, &tempProtect)) {
        if (logFile.is_open()) {
            logFile << "Warning: Failed to restore memory protection during unhook. Error: " << GetLastError() << std::endl;
        }
    }

    hookInstalled = false;
    pOriginalBeep = nullptr; // Reset the pointer to indicate no hook is active
    if (logFile.is_open()) {
        logFile << "Beep hook uninstalled successfully." << std::endl;
    }
}
