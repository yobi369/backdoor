import ctypes
from ctypes import wintypes

# Define necessary Windows structures and constants
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Constants for CreateToolhelp32Snapshot
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
MAX_PATH = 260

# PROCESSENTRY32 structure
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)), # In Python, this is often just ULONG_PTR or similar, but POINTER for direct translation
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * MAX_PATH)
    ]

# Function prototypes for Kernel32 functions
CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.restype = wintypes.HANDLE
CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

Process32First = kernel32.Process32First
Process32First.restype = wintypes.BOOL
Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]

Process32Next = kernel32.Process32Next
Process32Next.restype = wintypes.BOOL
Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes = [wintypes.HANDLE]


def list_processes_windows_impl():
    """
    Lists running processes on Windows.
    Returns a list of dictionaries, each containing PID, ParentPID, and ExeFile,
    or an error string.
    """
    processes = []
    h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    if h_snapshot == INVALID_HANDLE_VALUE:
        error_code = ctypes.get_last_error()
        return f"Error: CreateToolhelp32Snapshot failed with code {error_code}"

    pe32 = PROCESSENTRY32()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if not Process32First(h_snapshot, ctypes.byref(pe32)):
        error_code = ctypes.get_last_error()
        CloseHandle(h_snapshot)
        return f"Error: Process32First failed with code {error_code}"

    while True:
        try:
            exe_file_str = pe32.szExeFile.decode('utf-8', errors='replace')
        except Exception: # Fallback for decoding issues, though 'replace' should handle most
            exe_file_str = "<decoding_error>"

        processes.append({
            "PID": pe32.th32ProcessID,
            "ParentPID": pe32.th32ParentProcessID,
            "ExeFile": exe_file_str
        })
        if not Process32Next(h_snapshot, ctypes.byref(pe32)):
            break

    CloseHandle(h_snapshot)
    return processes

# For GetModuleFileNameEx and other process functions
psapi = ctypes.WinDLL('Psapi', use_last_error=True) # PSAPI.DLL

# Constants for OpenProcess
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# For GetModuleFileNameEx
GetModuleFileNameExW = psapi.GetModuleFileNameExW
GetModuleFileNameExW.restype = wintypes.DWORD
GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]

OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]


def get_process_details_windows_impl(pid_str):
    """
    Gets details for a specific process on Windows.
    Returns a dictionary with details or an error string.
    """
    try:
        pid = int(pid_str)
    except ValueError:
        return "Error: Invalid PID format. PID must be an integer."

    details = {"PID": pid}

    # PROCESS_QUERY_INFORMATION is needed for GetModuleFileNameEx
    # PROCESS_VM_READ might be needed for other details later, good to include
    h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

    if not h_process: # OpenProcess returns NULL (0) on failure
        error_code = ctypes.get_last_error()
        # Common error codes: 5 (Access Denied), 87 (Invalid Parameter - often for system/idle process)
        return f"Error: OpenProcess failed for PID {pid} with code {error_code}. (May require higher privileges or PID is invalid/protected)"

    # Get executable path
    exe_path_buffer = ctypes.create_unicode_buffer(MAX_PATH)
    path_len = GetModuleFileNameExW(h_process, None, exe_path_buffer, MAX_PATH)

    if path_len == 0:
        error_code = ctypes.get_last_error()
        details["ExecutablePath"] = f"<Error getting path: {error_code}>"
    else:
        details["ExecutablePath"] = exe_path_buffer.value

    # TODO: Add more details like Parent PID (requires another snapshot or different API),
    # loaded modules, memory usage, etc. as per plan.
    # For now, just PID and Path.

    CloseHandle(h_process)
    return details

# For ReadProcessMemory
ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.restype = wintypes.BOOL
ReadProcessMemory.argtypes = [
    wintypes.HANDLE,  # hProcess
    wintypes.LPCVOID, # lpBaseAddress
    wintypes.LPVOID,  # lpBuffer
    ctypes.c_size_t,  # nSize
    ctypes.POINTER(ctypes.c_size_t) # lpNumberOfBytesRead
]

def read_process_memory_windows_impl(pid_str, address_str, size_str):
    """
    Reads memory from a specific process on Windows.
    Returns a dictionary with hex-encoded data or an error string.
    """
    try:
        pid = int(pid_str)
        address = int(address_str, 16) # Expecting hex address
        size = int(size_str)
        if size <= 0 or size > 65536: # Arbitrary reasonable limit for one read
             return "Error: Invalid size. Must be between 1 and 65536."
    except ValueError:
        return "Error: Invalid PID, address, or size format. PID/size must be integers, address in hex."

    h_process = OpenProcess(PROCESS_VM_READ, False, pid)
    if not h_process:
        error_code = ctypes.get_last_error()
        return f"Error: OpenProcess failed for PID {pid} with code {error_code}. (May require higher privileges or PID is invalid/protected)"

    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)

    success = ReadProcessMemory(
        h_process,
        wintypes.LPCVOID(address),
        buffer,
        size,
        ctypes.byref(bytes_read)
    )

    CloseHandle(h_process)

    if not success:
        error_code = ctypes.get_last_error()
        return f"Error: ReadProcessMemory failed for PID {pid} at address 0x{address:X} with code {error_code}."

    if bytes_read.value == 0 and size > 0 : # Check if any bytes were actually read, if requested
        # This can happen if the address is valid but not readable, or other edge cases
        # where ReadProcessMemory might succeed but not read anything.
        return f"Warning: ReadProcessMemory succeeded but read 0 bytes from PID {pid} at address 0x{address:X} for size {size}."


    # Return data as hex string for easy display/use
    return {"pid": pid, "address": f"0x{address:X}", "size_requested": size, "bytes_read": bytes_read.value, "data_hex": buffer.raw[:bytes_read.value].hex()}

# For VirtualQueryEx
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),    # MEM_COMMIT, MEM_FREE, MEM_RESERVE
        ("Protect", wintypes.DWORD),  # PAGE_READWRITE, PAGE_EXECUTE_READ, etc.
        ("Type", wintypes.DWORD)      # MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
    ]

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.restype = ctypes.c_size_t
VirtualQueryEx.argtypes = [
    wintypes.HANDLE,         # hProcess
    wintypes.LPCVOID,        # lpAddress
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), # lpBuffer
    ctypes.c_size_t          # dwLength
]

# Memory States and Protections
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
# Readable pages (simplified check, actual readable means not PAGE_NOACCESS and not PAGE_GUARD)
# For simplicity, we'll consider pages readable if they don't have PAGE_NOACCESS and are committed.
# A more robust check would involve checking specific readable flags like PAGE_READONLY, PAGE_READWRITE etc.
# and excluding PAGE_GUARD and PAGE_NOACCESS.

def scan_process_memory_windows_impl(pid_str, pattern_type_str, pattern_str):
    """
    Scans the memory of a specific process on Windows for a given pattern.
    Returns a list of addresses where the pattern was found or an error string.
    """
    try:
        pid = int(pid_str)
    except ValueError:
        return "Error: Invalid PID format. PID must be an integer."

    if pattern_type_str.lower() == "string":
        try:
            pattern_bytes = pattern_str.encode('utf-8') # Default to UTF-8 for strings
        except UnicodeEncodeError:
            return "Error: Could not encode string pattern to UTF-8."
    elif pattern_type_str.lower() == "bytes":
        try:
            pattern_bytes = bytes.fromhex(pattern_str)
        except ValueError:
            return "Error: Invalid hex string for bytes pattern."
    else:
        return "Error: Invalid pattern_type. Must be 'string' or 'bytes'."

    if not pattern_bytes:
        return "Error: Pattern cannot be empty."

    h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h_process:
        error_code = ctypes.get_last_error()
        return f"Error: OpenProcess failed for PID {pid} with code {error_code}."

    found_addresses = []
    mem_info = MEMORY_BASIC_INFORMATION()
    current_address = wintypes.LPVOID(0)
    max_address = wintypes.LPVOID(0x7FFFFFFF0000) # User-mode address space limit (approx) for 64-bit
    # For 32-bit, it would be 0x7FFF0000. A more robust way is needed if targeting both precisely.
    # This is a simplification.

    while current_address.value < max_address.value :
        bytes_written = VirtualQueryEx(h_process, current_address, ctypes.byref(mem_info), ctypes.sizeof(mem_info))
        if bytes_written == 0: # Reached end of address space or error
            # error_code = ctypes.get_last_error()
            # print(f"VirtualQueryEx failed or finished at {current_address.value:X} with code {error_code}")
            break # Stop scanning

        # Check if the memory region is committed and readable
        # Readable if not PAGE_NOACCESS and not PAGE_GUARD (0x100).
        # For simplicity, we check State == MEM_COMMIT and Protect != PAGE_NOACCESS and not (Protect & 0x100)
        is_committed = mem_info.State == MEM_COMMIT
        is_readable = (mem_info.Protect != PAGE_NOACCESS) and not (mem_info.Protect & 0x0100) # Not PAGE_GUARD

        if is_committed and is_readable:
            region_base = mem_info.BaseAddress
            region_size = mem_info.RegionSize

            # Read the region in chunks to avoid very large single reads
            chunk_size = 65536  # Read in 64KB chunks
            offset_in_region = 0

            while offset_in_region < region_size:
                read_addr = region_base + offset_in_region
                size_to_read = min(chunk_size, region_size - offset_in_region)

                buffer = ctypes.create_string_buffer(size_to_read)
                bytes_read_count = ctypes.c_size_t(0)

                rpm_success = ReadProcessMemory(
                    h_process,
                    wintypes.LPCVOID(read_addr),
                    buffer,
                    size_to_read,
                    ctypes.byref(bytes_read_count)
                )

                if rpm_success and bytes_read_count.value > 0:
                    chunk_data = buffer.raw[:bytes_read_count.value]
                    # Scan chunk_data for pattern_bytes
                    idx = 0
                    while True:
                        found_idx = chunk_data.find(pattern_bytes, idx)
                        if found_idx == -1:
                            break
                        found_addresses.append(f"0x{(read_addr + found_idx):X}")
                        idx = found_idx + 1 # Continue search after this find

                offset_in_region += chunk_size

        # Move to the next region
        if mem_info.RegionSize == 0: # Should not happen if VirtualQueryEx succeeded
             break
        current_address.value = mem_info.BaseAddress + mem_info.RegionSize
        if current_address.value is None or current_address.value < mem_info.BaseAddress : # Overflow or error
            break


    CloseHandle(h_process)

    if not found_addresses:
        return f"Pattern '{pattern_str}' (type: {pattern_type_str}) not found in readable memory of PID {pid}."
    return {"pid": pid, "pattern_type": pattern_type_str, "pattern": pattern_str, "found_at_addresses": found_addresses}


if __name__ == '__main__':
    # This section can be used for direct testing of windows_utils.py functions
    # For example, when developing list_processes_windows_impl, you could call it here
    # and print the results to the console if running this file directly on Windows.
    print("windows_utils.py executed directly (for testing purposes).")
    # Example:
    # processes = list_processes_windows_impl()
    # if processes:
    #     for p in processes:
    #         print(p)
