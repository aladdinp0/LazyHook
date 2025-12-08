#pragma once
#include <Windows.h>

typedef struct PeImage {
    PVOID ImageBase;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
#ifdef _WIN64
    PIMAGE_OPTIONAL_HEADER64 OptionalHeader;
#else
    PIMAGE_OPTIONAL_HEADER32 OptionalHeader;
#endif
    IMAGE_FILE_HEADER FileHeader;
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
} PeImage;

inline PeImage ParsePeImage(LPCSTR ImageName) {
    PVOID ImageBase = GetModuleHandleA(ImageName);
    DWORD_PTR PeBase = (DWORD_PTR)ImageBase;
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)ImageBase;

#ifdef _WIN64
    PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(PeBase + Dos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER64 OptionalHeader = &NtHeaders->OptionalHeader;
#else
    PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)(PeBase + Dos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER32 OptionalHeader = &NtHeaders->OptionalHeader;
#endif

    IMAGE_FILE_HEADER FileHeader = NtHeaders->FileHeader;

    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(PeBase + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(PeBase + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    return PeImage{
        ImageBase,
        Dos,
        NtHeaders,
        OptionalHeader,
        FileHeader,
        ImportDescriptor,
        ExportDirectory
    };
}
