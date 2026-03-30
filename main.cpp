#include <print>
#include <vector>
#include <variant>
#include "Windef.hpp"
_IMAGE_DOS_HEADER DosHeader;
FILE_HEADER FileHeader;
std::vector<SECTION_HEADER> SECTION_TABLE;
OPTIONAL_HEADER OptionalHeader; // OptionalHeader64 for 64bit
std::vector<IMG_IMPORT_DESCRIPTOR> IMG_DESCRIPTOR;
IMG_EXPORT_DIRECTORY EXPORT_DIRECTORY;
HANDLE File;

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

auto ReadDosHeader() -> void
{
    SetFilePointer(File, 0, 0, FILE_BEGIN);
    if (!ReadFile(File, &DosHeader, sizeof(_IMAGE_DOS_HEADER), 0, 0))
    {
        println("Failed to read header 0x{:0X}", GetLastError());
        exit(1);
    }
}

auto ReadFileHeader() -> void
{
    SetFilePointer(File, DosHeader.e_lfanew, 0, FILE_BEGIN);
    if (!ReadFile(File, &FileHeader, sizeof(FILE_HEADER), 0, 0))
    {
        println("Failed to read header 0x{:0X}", GetLastError());
        exit(1);
    }
}

auto ReadOptionalHeader() -> void
{
    SetFilePointer(File, DosHeader.e_lfanew + sizeof(FILE_HEADER), 0, FILE_BEGIN);
    if (!ReadFile(File, &OptionalHeader, sizeof(OptionalHeader), 0, 0))
    {
        println("Failed to read header 0x{:0X}", GetLastError());
        exit(1);
    }
}
auto ReadSectionTable() -> void
{
    SECTION_TABLE.resize(FileHeader.NumberOfSections);
    if (!ReadFile(File, SECTION_TABLE.data(), (sizeof(SECTION_HEADER) * FileHeader.NumberOfSections), 0, 0))
    {
        println("Failed to read header 0x{:0X}", GetLastError());
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
            println("Failed to read structure 0x{:0X}", GetLastError());
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
        println("FAILED to find Any Related Sections");
        exit(1);
    }
    DWORD Offset = OptionalHeader.DataDirectory[EXPORT].VirtualAddress - SECTION_TABLE[SECTION_INDEX].VirtualAddress + SECTION_TABLE[SECTION_INDEX].PointerToRawData;
    SetFilePointer(File, Offset, 0, FILE_BEGIN);
    if (!ReadFile(File, &EXPORT_DIRECTORY, sizeof(IMG_EXPORT_DIRECTORY), 0, 0))
    {
        println("Failed to read header 0x{:0X}", GetLastError());
        exit(1);
    }
}

auto GetExportOffsets(DWORD &Offset_Functions, DWORD &Offset_Names, DWORD &Offset_Ordinals) -> void
{
    int SECTION_INDEX = CalculateSectionLocation(OptionalHeader.DataDirectory[EXPORT].VirtualAddress);
    Offset_Functions = EXPORT_DIRECTORY.AddressOfFunctions - SECTION_TABLE[SECTION_INDEX].VirtualAddress + SECTION_TABLE[SECTION_INDEX].PointerToRawData;
    Offset_Ordinals = EXPORT_DIRECTORY.AddressOfNameOrdinals - SECTION_TABLE[SECTION_INDEX].VirtualAddress + SECTION_TABLE[SECTION_INDEX].PointerToRawData;
    DWORD RVA_Offset_Names = (EXPORT_DIRECTORY.AddressOfNames - SECTION_TABLE[SECTION_INDEX].VirtualAddress + SECTION_TABLE[SECTION_INDEX].PointerToRawData);
    SetFilePointer(File, RVA_Offset_Names, 0, FILE_BEGIN);
    ReadFile(File, &Offset_Names, sizeof(DWORD), 0, 0);
    Offset_Names += -SECTION_TABLE[SECTION_INDEX].VirtualAddress + SECTION_TABLE[SECTION_INDEX].PointerToRawData;
}

void ReadExportNames(std::vector<std::string> &names,DWORD &Offset_Names)
{
    int SECTION_INDEX = CalculateSectionLocation(OptionalHeader.DataDirectory[EXPORT].VirtualAddress);

    DWORD sectionEnd = SECTION_TABLE[SECTION_INDEX].PointerToRawData + SECTION_TABLE[SECTION_INDEX].SizeOfRawData;

    DWORD blockSize = sectionEnd - Offset_Names;

    std::vector<char> buffer(blockSize);
    DWORD bytesRead;
    
    SetFilePointer(File, Offset_Names, 0, FILE_BEGIN);
    ReadFile(File, buffer.data(), blockSize, &bytesRead, 0);

    const char *ptr = buffer.data();
    const char *end = ptr + bytesRead;

    while (ptr < end && names.size() < EXPORT_DIRECTORY.NumberOfNames)
    {
        std::string name(ptr);
        if (!name.empty())
            names.push_back(name);
        ptr += name.size() + 1;
    }

}

int main(int argc, char *argv[])
{
    File = CreateFileA("ntdll_dump.dll", GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (File == INVALID_HANDLE_VALUE)
    {
        println("Failed to open file 0x{:0X}", GetLastError());
        return GetLastError();
    }
    DWORD Offset_Functions = 0;
    DWORD Offset_Ordinals = 0;
    DWORD Offset_Names = 0;
    std::vector<std::string> names;
    std::vector<DWORD> EXPORT_TABLE(EXPORT_DIRECTORY.NumberOfFunctions);

    ReadDosHeader();
    ReadFileHeader();
    ReadOptionalHeader();
    ReadSectionTable();
    ReadExportDirectory();
    GetExportOffsets(Offset_Functions, Offset_Names, Offset_Ordinals);
    ReadExportNames(names,Offset_Names);

    EXPORT_TABLE.resize(EXPORT_DIRECTORY.NumberOfFunctions);
    SetFilePointer(File, Offset_Functions, 0, FILE_BEGIN);
    ReadFile(File, EXPORT_TABLE.data(),(sizeof(DWORD) * EXPORT_DIRECTORY.NumberOfFunctions), 0, 0);
    
    for (auto &c : names)
        println("{}", c);


    CloseHandle(File);
    return 0;
}