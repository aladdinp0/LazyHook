#pragma once
#include <Windows.h>
#include <cstdio>
#include "PEParse/PEParse.h"

namespace LazyHook
{
    struct VehHookState {
        PVOID OriginalFunction;
        PVOID HookFunction;
        DWORD DrIndex;
        BOOL IsActive;
        BOOL IsExecuting;
    };

    static VehHookState IatState{};
    static VehHookState EatState{};
    static PVOID VehHandle = nullptr;

    VehHookState* GetIatState() { return &IatState; }
    VehHookState* GetEatState() { return &EatState; }

    DWORD FindFreeDrIndex(PCONTEXT Ctx)
    {
        for (DWORD i = 0; i < 4; i++)
        {
            if (!(Ctx->Dr7 & (1ULL << (i * 2))))
                return i;
        }
        return (DWORD)-1;
    }

    BOOL SetHardwareBreakpoint(PVOID Address, DWORD DrIndex)
    {
        HANDLE Thread = GetCurrentThread();
        CONTEXT Ctx = { 0 };
        Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext(Thread, &Ctx))
            return FALSE;

        switch (DrIndex)
        {
        case 0: Ctx.Dr0 = (DWORD_PTR)Address; break;
        case 1: Ctx.Dr1 = (DWORD_PTR)Address; break;
        case 2: Ctx.Dr2 = (DWORD_PTR)Address; break;
        case 3: Ctx.Dr3 = (DWORD_PTR)Address; break;
        default: return FALSE;
        }

        Ctx.Dr7 |= (1ULL << (DrIndex * 2));
        Ctx.Dr7 &= ~(3ULL << (16 + DrIndex * 4));
        Ctx.Dr7 &= ~(3ULL << (18 + DrIndex * 4));

        return SetThreadContext(Thread, &Ctx);
    }

    BOOL RemoveHardwareBreakpoint(DWORD DrIndex)
    {
        HANDLE Thread = GetCurrentThread();
        CONTEXT Ctx = { 0 };
        Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext(Thread, &Ctx))
            return FALSE;

        Ctx.Dr7 &= ~(1ULL << (DrIndex * 2));

        switch (DrIndex)
        {
        case 0: Ctx.Dr0 = 0; break;
        case 1: Ctx.Dr1 = 0; break;
        case 2: Ctx.Dr2 = 0; break;
        case 3: Ctx.Dr3 = 0; break;
        default: return FALSE;
        }

        return SetThreadContext(Thread, &Ctx);
    }

    LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS Info)
    {
        if (Info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
            return EXCEPTION_CONTINUE_SEARCH;

#ifdef _WIN64
        DWORD_PTR Rip = Info->ContextRecord->Rip;
#else
        DWORD Rip = Info->ContextRecord->Eip;
#endif

        VehHookState* List[2] = { &IatState, &EatState };

        for (int i = 0; i < 2; i++)
        {
            VehHookState* S = List[i];
            if (!S->IsActive || S->IsExecuting) continue;

            if (Rip == (DWORD_PTR)S->OriginalFunction)
            {
                printf("[*] VEH Triggered for %p\n", S->OriginalFunction);

#ifdef _WIN64
                Info->ContextRecord->Rip = (DWORD_PTR)S->HookFunction;
#else
                Info->ContextRecord->Eip = (DWORD)S->HookFunction;
#endif

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    BOOL InstallHwbp(PVOID Address, PVOID Hook, VehHookState* State)
    {
        CONTEXT Ctx = { 0 };
        Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(GetCurrentThread(), &Ctx);

        DWORD DrIndex = FindFreeDrIndex(&Ctx);
        if (DrIndex == (DWORD)-1)
            return FALSE;

        if (!SetHardwareBreakpoint(Address, DrIndex))
            return FALSE;

        State->OriginalFunction = Address;
        State->HookFunction = Hook;
        State->DrIndex = DrIndex;
        State->IsActive = TRUE;
        State->IsExecuting = FALSE;

        if (!VehHandle)
        {
            VehHandle = AddVectoredExceptionHandler(1, VectoredHandler);
            if (!VehHandle) return FALSE;
        }

        return TRUE;
    }

    BOOL RemoveHwbp(VehHookState* State)
    {
        if (!State->IsActive) return FALSE;

        if (!RemoveHardwareBreakpoint(State->DrIndex))
            return FALSE;

        State->IsActive = FALSE;
        return TRUE;
    }

    template<typename Ret, typename... Args>
    Ret CallOriginal(VehHookState* State, Args... args)
    {
        RemoveHardwareBreakpoint(State->DrIndex);

        typedef Ret(*FuncType)(Args...);
        Ret Result = ((FuncType)State->OriginalFunction)(args...);

        SetHardwareBreakpoint(State->OriginalFunction, State->DrIndex);

        return Result;
    }

    BOOL HookIAT(LPCSTR Module, LPCSTR Proc, PVOID HookFunc, PVOID* OutOriginal)
    {
        PeImage Pe = ParsePeImage(0);
        DWORD_PTR Base = (DWORD_PTR)Pe.ImageBase;

        PIMAGE_IMPORT_DESCRIPTOR Imp = Pe.ImportDescriptor;

        while (Imp->Name)
        {
            LPCSTR Name = (LPCSTR)(Base + Imp->Name);

            if (_strcmpi(Name, Module) == 0)
            {
                auto OrigThunk = (PIMAGE_THUNK_DATA)(Base + Imp->OriginalFirstThunk);
                auto Thunk = (PIMAGE_THUNK_DATA)(Base + Imp->FirstThunk);

                while (OrigThunk->u1.AddressOfData)
                {
                    auto ByName = (PIMAGE_IMPORT_BY_NAME)(Base + OrigThunk->u1.AddressOfData);

                    if (_strcmpi(ByName->Name, Proc) == 0)
                    {
                        *OutOriginal = (PVOID)Thunk->u1.Function;
                        printf("[+] IAT Original Address: %p\n", *OutOriginal);

                        return InstallHwbp(*OutOriginal, HookFunc, &IatState);
                    }

                    OrigThunk++;
                    Thunk++;
                }
            }

            Imp++;
        }

        return FALSE;
    }

    BOOL HookEAT(LPCSTR Module, LPCSTR Proc, PVOID HookFunc, PVOID* OutOriginal)
    {
        PeImage Pe = ParsePeImage(Module);
        DWORD_PTR Base = (DWORD_PTR)Pe.ImageBase;

        auto Dir = Pe.ExportDirectory;

        PDWORD Names = (PDWORD)(Base + Dir->AddressOfNames);
        PDWORD Funcs = (PDWORD)(Base + Dir->AddressOfFunctions);
        PWORD Ords = (PWORD)(Base + Dir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < Dir->NumberOfNames; i++)
        {
            LPCSTR Current = (LPCSTR)(Base + Names[i]);

            if (_strcmpi(Current, Proc) == 0)
            {
                DWORD RVA = Funcs[Ords[i]];
                *OutOriginal = (PVOID)(Base + RVA);

                printf("[+] EAT Original Address: %p\n", *OutOriginal);

                return InstallHwbp(*OutOriginal, HookFunc, &EatState);
            }
        }

        return FALSE;
    }

    BOOL UnhookIAT() { return RemoveHwbp(&IatState); }
    BOOL UnhookEAT() { return RemoveHwbp(&EatState); }
}