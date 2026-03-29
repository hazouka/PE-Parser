#include <print>
#include <vector>
#include <variant>
#include "Windef.hpp"
_IMAGE_DOS_HEADER DosHeader;
FILE_HEADER FileHeader;
std::vector<SECTION_HEADER> SECTION_TABLE;
OPTIONAL_HEADER OptionalHeader; //OptionalHeader64 for 64bit
std::vector<IMG_IMPORT_DESCRIPTOR> IMG_DESCRIPTOR;

using std::print,std::println;

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

auto Read_Dos_Header(HANDLE &File) -> void
{
    SetFilePointer(File, 0, 0, FILE_BEGIN);
    if (!ReadFile(File, &DosHeader, sizeof(_IMAGE_DOS_HEADER), 0, 0))
    {
        println("Failed to read header 0x{:0X}", GetLastError());
        exit(1);
    }
}

auto Read_File_Header(HANDLE &File) -> void
{
    SetFilePointer(File, DosHeader.e_lfanew, 0, FILE_BEGIN);
    if (!ReadFile(File, &FileHeader, sizeof(FILE_HEADER), 0, 0))
    {
        println("Failed to read header 0x{:0X}", GetLastError());
        exit(1);
    }
}

auto Read_Optional_Header(HANDLE &File) -> void
{
    SetFilePointer(File, DosHeader.e_lfanew + sizeof(FILE_HEADER), 0, FILE_BEGIN);
    if (!ReadFile(File, &OptionalHeader, sizeof(OptionalHeader), 0, 0))
    {
        println("Failed to read header 0x{:0X}", GetLastError());
        exit(1);
    }
}
auto Read_Section_Table(HANDLE &File) -> void
{
    SECTION_TABLE.resize(FileHeader.NumberOfSections);
    if (!ReadFile(File, SECTION_TABLE.data(), (sizeof(SECTION_HEADER) * FileHeader.NumberOfSections), 0, 0))
    {
        println("Failed to read header 0x{:0X}", GetLastError());
        exit(1);
    }
}

auto Import_Table_Section() -> int
{
    for (int i = 0; i < FileHeader.NumberOfSections; i++)
    {
        DWORD Section_Rva = SECTION_TABLE[i].VirtualAddress;
        DWORD IMPORT_RVA = OptionalHeader.DataDirectory[1].VirtualAddress;
        if (Section_Rva <= IMPORT_RVA && IMPORT_RVA <= (Section_Rva + SECTION_TABLE[i].Misc.VirtualSize))
        {
            println("Found at Section {}",(char *)(&SECTION_TABLE[i].Name));
            return i;
        }
    }
    return 0;
}

auto Read_IMAGE_IMPORT_DESCRIPTOR(HANDLE &File) -> void
{
    int IT_SECTION_INDEX = Import_Table_Section();
    DWORD Offset = OptionalHeader.DataDirectory[IMPORT].VirtualAddress - SECTION_TABLE[IT_SECTION_INDEX].VirtualAddress + SECTION_TABLE[IT_SECTION_INDEX].PointerToRawData;
    SetFilePointer(File,Offset,0,FILE_BEGIN);
    while(true)
    {
        IMG_IMPORT_DESCRIPTOR desc{};
        if (!ReadFile(File, &desc, sizeof(IMG_IMPORT_DESCRIPTOR), 0, 0))
        {
            println("Failed to read structure 0x{:0X}", GetLastError());
            exit(1);
        }

        if (desc.Name == 0) break;

        IMG_DESCRIPTOR.push_back(desc);
    }
}


int main(int argc, char *argv[])
{
    HANDLE File = CreateFileA("Read.exe", GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (File == INVALID_HANDLE_VALUE)
    {
        println("Failed to open file 0x{:0X}", GetLastError());
        return GetLastError();
    }

    Read_Dos_Header(File);
    Read_File_Header(File);
    Read_Optional_Header(File);
    Read_Section_Table(File);
    Read_IMAGE_IMPORT_DESCRIPTOR(File);
    
    CloseHandle(File);
    return 0;
}   