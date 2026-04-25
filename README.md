# PE Parser

A Windows PE (Portable Executable) file parser written in modern C++.

## Why

I only built this to learn more about the PE format and the best way would be to do it practically :D

## What it does

- Parses the **DOS header**, **File header**, and **Optional header** (PE32 and PE64)
- Walks the **section table** and resolves RVAs to raw file offsets
- Parses the **Export Directory** — function names, ordinals, and addresses
- Parses the **Import Descriptor** table

## Usage

```
./Parser <file>
```

## Note

This should work on both **Windows** and **Linux** because it doesnt use any platform dependent apis.

I used `std::variant` to hold the correct OptionalHeader so its able to parse both 32 and 64 bit applicatios.