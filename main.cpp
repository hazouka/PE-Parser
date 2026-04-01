#include <print>
#include <vector>
#include <ranges>
#include "Windef.hpp"
using std::print, std::println;
enum DATA_DIR
{
    EXPORT,
    IMPORT,
    RESOURCE,
    EXCEPTION,
    SECURITY,
    BASE_RELOCATION_TABLE,
    DEBUG_DIRECTORY,
    COPYRIGHT_SPECIFIC_DATA,
    GLOBAL_PTR,
    TLS_DIRECTORY,
    LOAD_CONFIG_DIRECTORY,
    BOUND_IMPORT_DIRECTORY,
    IMPORT_ADDRESS_TABLE,
    DLLD,
    CLR_DIRECTORY,
    RESERVED
};

_IMAGE_DOS_HEADER DosHeader;
FILE_HEADER FileHeader;
std::vector<SECTION_HEADER> SECTION_TABLE;
OPTIONAL_HEADER OptionalHeader; // OptionalHeader64 for 64bit
std::vector<IMG_IMPORT_DESCRIPTOR> IMG_DESCRIPTOR;
IMG_EXPORT_DIRECTORY EXPORT_DIRECTORY;
HANDLE File;
DWORD Offset_Functions = 0;
DWORD Offset_Ordinals = 0;
DWORD Offset_Names = 0;
std::vector<std::string> names;
std::vector<DWORD> EXPORT_TABLE;
std::vector<DWORD> EXPORT_NAME_TABLE;
std::vector<WORD> EXPORT_ORDINAL_TABLE;

auto ReadDosHeader() -> void
{
    SetFilePointer(File, 0, 0, FILE_BEGIN);
    if (!ReadFile(File, &DosHeader, sizeof(_IMAGE_DOS_HEADER), 0, 0))
    {
        println("failed to read DOS header 0x{:0X}", GetLastError());
        exit(1);
    }
}

auto ReadFileHeader() -> void
{
    SetFilePointer(File, DosHeader.e_lfanew, 0, FILE_BEGIN);
    if (!ReadFile(File, &FileHeader, sizeof(FILE_HEADER), 0, 0))
    {
        println("failed to read file header 0x{:0X}", GetLastError());
        exit(1);
    }
}

auto ReadOptionalHeader() -> void
{
    SetFilePointer(File, DosHeader.e_lfanew + sizeof(FILE_HEADER), 0, FILE_BEGIN);
    if (!ReadFile(File, &OptionalHeader, sizeof(OptionalHeader), 0, 0))
    {
        println("failed to read optional header 0x{:0X}", GetLastError());
        exit(1);
    }
}
auto ReadSectionTable() -> void
{
    SECTION_TABLE.resize(FileHeader.NumberOfSections);
    if (!ReadFile(File, SECTION_TABLE.data(), (sizeof(SECTION_HEADER) * FileHeader.NumberOfSections), 0, 0))
    {
        println("failed to read section table 0x{:0X}", GetLastError());
        exit(1);
    }
}

auto CalculateSectionLocation(const DWORD &RVA) -> int
{
    for (int i = 0; i < FileHeader.NumberOfSections; i++)
    {
        DWORD Section_Rva = SECTION_TABLE[i].VirtualAddress;
        if (Section_Rva <= RVA && RVA <= (Section_Rva + SECTION_TABLE[i].Misc.VirtualSize))
        {
            return i;
        }
    }
    return -1;
}

auto ReadImportDescriptor() -> void
{
    int IT_SECTION_INDEX = CalculateSectionLocation(OptionalHeader.DataDirectory[IMPORT].VirtualAddress);
    DWORD Offset = OptionalHeader.DataDirectory[IMPORT].VirtualAddress - SECTION_TABLE[IT_SECTION_INDEX].VirtualAddress + SECTION_TABLE[IT_SECTION_INDEX].PointerToRawData;
    SetFilePointer(File, Offset, 0, FILE_BEGIN);
    while (true)
    {
        IMG_IMPORT_DESCRIPTOR desc{};
        if (!ReadFile(File, &desc, sizeof(IMG_IMPORT_DESCRIPTOR), 0, 0))
        {
            println("failed to read import descriptor 0x{:0X}", GetLastError());
            exit(1);
        }

        if (desc.Name == 0)
            break;

        IMG_DESCRIPTOR.push_back(desc);
    }
}

auto ReadExportDirectory() -> void
{
    int SECTION_INDEX = CalculateSectionLocation(OptionalHeader.DataDirectory[EXPORT].VirtualAddress);
    if (SECTION_INDEX == -1)
    {
        println("failed to locate export directory section");
        exit(1);
    }
    DWORD Offset = OptionalHeader.DataDirectory[EXPORT].VirtualAddress - SECTION_TABLE[SECTION_INDEX].VirtualAddress + SECTION_TABLE[SECTION_INDEX].PointerToRawData;
    SetFilePointer(File, Offset, 0, FILE_BEGIN);
    if (!ReadFile(File, &EXPORT_DIRECTORY, sizeof(IMG_EXPORT_DIRECTORY), 0, 0))
    {
        println("failed to read export directory 0x{:0X}", GetLastError());
        exit(1);
    }
}
auto ReadExportTables() -> void
{
    EXPORT_TABLE.resize(EXPORT_DIRECTORY.NumberOfFunctions);
    EXPORT_NAME_TABLE.resize(EXPORT_DIRECTORY.NumberOfNames);
    EXPORT_ORDINAL_TABLE.resize(EXPORT_DIRECTORY.NumberOfNames);

    SetFilePointer(File, Offset_Functions, 0, FILE_BEGIN);
    if (!ReadFile(File, EXPORT_TABLE.data(), (sizeof(DWORD) * EXPORT_DIRECTORY.NumberOfFunctions), 0, 0))
    {
        println("failed to read function address table 0x{:0X}", GetLastError());
        exit(1);
    }
    SetFilePointer(File, Offset_Names, 0, FILE_BEGIN);
    if (!ReadFile(File, EXPORT_NAME_TABLE.data(), (sizeof(DWORD) * EXPORT_DIRECTORY.NumberOfNames), 0, 0))
    {
        println("failed to read export name pointer table 0x{:0X}", GetLastError());
        exit(1);
    }
    SetFilePointer(File, Offset_Ordinals, 0, FILE_BEGIN);
    if (!ReadFile(File, EXPORT_ORDINAL_TABLE.data(), (sizeof(WORD) * EXPORT_DIRECTORY.NumberOfNames), 0, 0))
    {
        println("failed to read export ordinal table 0x{:0X}", GetLastError());
        exit(1);
    }
}

auto GetExportOffsets() -> void
{
    int SECTION_INDEX = CalculateSectionLocation(OptionalHeader.DataDirectory[EXPORT].VirtualAddress);
    Offset_Functions = EXPORT_DIRECTORY.AddressOfFunctions - SECTION_TABLE[SECTION_INDEX].VirtualAddress + SECTION_TABLE[SECTION_INDEX].PointerToRawData;
    Offset_Ordinals = EXPORT_DIRECTORY.AddressOfNameOrdinals - SECTION_TABLE[SECTION_INDEX].VirtualAddress + SECTION_TABLE[SECTION_INDEX].PointerToRawData;
    Offset_Names = EXPORT_DIRECTORY.AddressOfNames - SECTION_TABLE[SECTION_INDEX].VirtualAddress + SECTION_TABLE[SECTION_INDEX].PointerToRawData;
}

auto ReadExportNames() -> void
{
    int SECTION_INDEX = CalculateSectionLocation(OptionalHeader.DataDirectory[EXPORT].VirtualAddress);
    SetFilePointer(File, Offset_Names, 0, FILE_BEGIN);
    std::vector<DWORD> Pointers(EXPORT_DIRECTORY.NumberOfNames);
    DWORD BytesRead = 0;
    ReadFile(File, Pointers.data(), (sizeof(DWORD) * EXPORT_DIRECTORY.NumberOfNames), &BytesRead, 0);
    for (int i = 0; i < EXPORT_DIRECTORY.NumberOfNames; i++)
    {
        DWORD nameOffset = Pointers[i] - SECTION_TABLE[SECTION_INDEX].VirtualAddress + SECTION_TABLE[SECTION_INDEX].PointerToRawData;

        SetFilePointer(File, nameOffset, 0, FILE_BEGIN);

        std::string name;
        char c;
        while (ReadFile(File, &c, sizeof(char), 0, 0) && c != '\0')
            name += c;
        names.push_back(name);
    }
}

auto ExportInfo(std::string_view Function) -> void
{
    int SECTION_INDEX = CalculateSectionLocation(OptionalHeader.DataDirectory[EXPORT].VirtualAddress);
    auto i = std::ranges::find(names, Function);
    int index = i - names.begin();
    auto OrdinalName = EXPORT_ORDINAL_TABLE[index];
    println("FUNCTION: {}", names.at(index));
    println("INDEX: {}", index);
    println("Name Ordinal: {}", OrdinalName);
    println("Ordinal: {}", OrdinalName + EXPORT_DIRECTORY.Base);
    println("RVA: {:0X}", EXPORT_TABLE[OrdinalName] - OptionalHeader.BaseOfCode);
}


int main(int argc, char *argv[])
{
    LPSTR ntdll = (LPSTR)"ntdll_dump.dll";
    LPSTR kernel = (LPSTR) "kernel32_dump.dll";
    LPSTR shell = (LPSTR) "shell32_dump.dll";
    File = CreateFileA(shell, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (File == INVALID_HANDLE_VALUE)
    {
        println("main failed to open {} 0x{:0X}", "", GetLastError());
        return GetLastError();
    }

    ReadDosHeader();
    ReadFileHeader();
    ReadOptionalHeader();
    ReadSectionTable();
    ReadExportDirectory();
    GetExportOffsets();
    ReadExportNames();
    ReadExportTables();

    CloseHandle(File);
    return 0;
}