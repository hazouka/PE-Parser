#include "Windef.hpp"
#include <fstream>
#include <print>
#include <ranges>
#include <variant>
#include <vector>
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
std::variant<OPTIONAL_HEADER, OPTIONAL_HEADER64> OptHeader;
std::vector<SECTION_HEADER> SECTION_TABLE;
std::vector<IMG_IMPORT_DESCRIPTOR> IMG_DESCRIPTOR;
IMG_EXPORT_DIRECTORY EXPORT_DIRECTORY;

std::ifstream File;

DWORD Offset_Functions = 0;
DWORD Offset_Ordinals  = 0;
DWORD Offset_Names     = 0;

std::vector<std::string> names;
std::vector<DWORD>       EXPORT_TABLE;
std::vector<DWORD>       EXPORT_NAME_TABLE;
std::vector<WORD>        EXPORT_ORDINAL_TABLE;


auto ReadDosHeader() -> void
{
  File.seekg(std::ios_base::beg);
  if (!File.read(reinterpret_cast<char*>(&DosHeader), sizeof(_IMAGE_DOS_HEADER)))
  {
    println("Failed to read the Dos Header");
    exit(1);
  }
}

auto ReadFileHeader() -> void
{
  File.seekg(DosHeader.e_lfanew, std::ios::beg);
  if (!File.read(reinterpret_cast<char*>(&FileHeader), sizeof(FILE_HEADER)))
  {
    println("Failed to read the File Header");
    exit(1);
  }
}


auto ReadNtHeaders() -> void
{
  ReadDosHeader();
  ReadFileHeader();

  File.seekg(DosHeader.e_lfanew + sizeof(FILE_HEADER), std::ios::beg);
  WORD Magic;
  if (!File.read(reinterpret_cast<char*>(&Magic), sizeof(WORD)))
  {
    println("Failed to read PE magic");
    exit(1);
  }


  File.seekg(DosHeader.e_lfanew + sizeof(FILE_HEADER), std::ios::beg);

  if (Magic == PE32)
  {
    OPTIONAL_HEADER header{};
    if (!File.read(reinterpret_cast<char*>(&header), sizeof(OPTIONAL_HEADER)))
    {
      println("Failed to read optional header (PE32)");
      exit(1);
    }
    OptHeader = header;
  }
  else if (Magic == PE64)
  {
    OPTIONAL_HEADER64 header{};
    if (!File.read(reinterpret_cast<char*>(&header), sizeof(OPTIONAL_HEADER64)))
    {
      println("Failed to read optional header (PE64)");
      exit(1);
    }
    OptHeader = header;
  }
  else
  {
    println("Unknown PE magic: {:X}", Magic);
    exit(1);
  }
}


auto ReadSectionTable() -> void
{
  File.seekg(DosHeader.e_lfanew + sizeof(FILE_HEADER) + FileHeader.SizeOfOptionalHeader, std::ios::beg);
  SECTION_TABLE.resize(FileHeader.NumberOfSections);
  if (!File.read(reinterpret_cast<char*>(SECTION_TABLE.data()),
                 sizeof(SECTION_HEADER) * FileHeader.NumberOfSections))
  {
    println("Failed to read section table");
    exit(1);
  }
}

auto CalculateSectionLocation(const DWORD& RVA) -> int
{
  for (int i = 0; i < FileHeader.NumberOfSections; i++)
  {
    DWORD Section_Rva = SECTION_TABLE[i].VirtualAddress;
    if (Section_Rva <= RVA && RVA <= (Section_Rva + SECTION_TABLE[i].Misc.VirtualSize))
      return i;
  }
  return -1;
}


auto ReadImportDescriptor() -> void
{
  std::visit([](auto& header) {
    int IT_SECTION_INDEX = CalculateSectionLocation(
        header.DataDirectory[IMPORT].VirtualAddress);

    DWORD Offset = header.DataDirectory[IMPORT].VirtualAddress -
                   SECTION_TABLE[IT_SECTION_INDEX].VirtualAddress +
                   SECTION_TABLE[IT_SECTION_INDEX].PointerToRawData;

    File.seekg(Offset, std::ios_base::beg);
    while (true)
    {
      IMG_IMPORT_DESCRIPTOR desc{};
      if (!File.read(reinterpret_cast<char*>(&desc), sizeof(IMG_IMPORT_DESCRIPTOR)))
      {
        println("Failed to read import descriptor");
        exit(1);
      }
      if (desc.Name == 0)
        break;
      IMG_DESCRIPTOR.push_back(desc);
    }
  }, OptHeader);
}


auto ReadExportDirectory() -> void
{
  std::visit([](auto& header) {
    int SECTION_INDEX = CalculateSectionLocation(
        header.DataDirectory[EXPORT].VirtualAddress);

    if (SECTION_INDEX == -1)
    {
      println("Failed to locate export directory section");
      exit(1);
    }

    DWORD Offset = header.DataDirectory[EXPORT].VirtualAddress -
                   SECTION_TABLE[SECTION_INDEX].VirtualAddress +
                   SECTION_TABLE[SECTION_INDEX].PointerToRawData;

    File.seekg(Offset, std::ios_base::beg);
    if (!File.read(reinterpret_cast<char*>(&EXPORT_DIRECTORY), sizeof(IMG_EXPORT_DIRECTORY)))
    {
      println("Failed to read export directory");
      exit(1);
    }
  }, OptHeader);
}

auto GetExportOffsets() -> void
{
  std::visit([](auto& header) {
    int SECTION_INDEX = CalculateSectionLocation(
        header.DataDirectory[EXPORT].VirtualAddress);

    Offset_Functions = EXPORT_DIRECTORY.AddressOfFunctions -
                       SECTION_TABLE[SECTION_INDEX].VirtualAddress +
                       SECTION_TABLE[SECTION_INDEX].PointerToRawData;

    Offset_Ordinals  = EXPORT_DIRECTORY.AddressOfNameOrdinals -
                       SECTION_TABLE[SECTION_INDEX].VirtualAddress +
                       SECTION_TABLE[SECTION_INDEX].PointerToRawData;

    Offset_Names     = EXPORT_DIRECTORY.AddressOfNames -
                       SECTION_TABLE[SECTION_INDEX].VirtualAddress +
                       SECTION_TABLE[SECTION_INDEX].PointerToRawData;
  }, OptHeader);
}

auto ReadExportTables() -> void
{
  EXPORT_TABLE.resize(EXPORT_DIRECTORY.NumberOfFunctions);
  EXPORT_NAME_TABLE.resize(EXPORT_DIRECTORY.NumberOfNames);
  EXPORT_ORDINAL_TABLE.resize(EXPORT_DIRECTORY.NumberOfNames);

  File.seekg(Offset_Functions, std::ios_base::beg);
  if (!File.read(reinterpret_cast<char*>(EXPORT_TABLE.data()),
                 sizeof(DWORD) * EXPORT_DIRECTORY.NumberOfFunctions))
  {
    println("Failed to read function address table");
    exit(1);
  }

  File.seekg(Offset_Names, std::ios_base::beg);
  if (!File.read(reinterpret_cast<char*>(EXPORT_NAME_TABLE.data()),
                 sizeof(DWORD) * EXPORT_DIRECTORY.NumberOfNames))
  {
    println("Failed to read export name pointer table");
    exit(1);
  }

  File.seekg(Offset_Ordinals, std::ios_base::beg);
  if (!File.read(reinterpret_cast<char*>(EXPORT_ORDINAL_TABLE.data()),
                 sizeof(WORD) * EXPORT_DIRECTORY.NumberOfNames))
  {
    println("Failed to read export ordinal table");
    exit(1);
  }
}

auto ReadExportNames() -> void
{
  std::visit([](auto& header) {
    int SECTION_INDEX = CalculateSectionLocation(
        header.DataDirectory[EXPORT].VirtualAddress);

    File.seekg(Offset_Names, std::ios_base::beg);
    std::vector<DWORD> Pointers(EXPORT_DIRECTORY.NumberOfNames);
    File.read(reinterpret_cast<char*>(Pointers.data()),
              sizeof(DWORD) * EXPORT_DIRECTORY.NumberOfNames);

    for (int i = 0; i < (int)EXPORT_DIRECTORY.NumberOfNames; i++)
    {
      DWORD nameOffset = Pointers[i] -
                         SECTION_TABLE[SECTION_INDEX].VirtualAddress +
                         SECTION_TABLE[SECTION_INDEX].PointerToRawData;

      File.seekg(nameOffset, std::ios_base::beg);

      std::string name;
      char c;
      while (File.read(&c, sizeof(char)) && c != '\0')
        name += c;
      names.push_back(name);
    }
  }, OptHeader);
}

auto ExportInfo(std::string_view Function) -> void
{
  std::visit([&](auto& header) {
    auto it = std::ranges::find(names, Function);
    if (it == names.end())
    {
      println("Function '{}' not found in export table", Function);
      return;
    }

    int index        = static_cast<int>(it - names.begin());
    auto OrdinalName = EXPORT_ORDINAL_TABLE[index];

    println("FUNCTION: {}",   names.at(index));
    println("INDEX: {}",      index);
    println("Name Ordinal: {}", OrdinalName);
    println("Ordinal: {}",    OrdinalName + EXPORT_DIRECTORY.Base);
    println("RVA: {:0X}",     EXPORT_TABLE[OrdinalName] - header.BaseOfCode);
  }, OptHeader);
}


int main(int argc, char* argv[])
{
  File.open(argv[1], std::ios::binary);
  if (!File.is_open())
  {
    println("Failed to open file");
    return 1;
  }

  ReadNtHeaders();
  ReadSectionTable();
  ReadExportDirectory();
  GetExportOffsets();
  ReadExportNames();
  ReadExportTables();
  ExportInfo("NtAllocateVirtualMemory");

  return 0;
}