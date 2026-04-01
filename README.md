### PE Parser

## Why

I only built this to learn as much as possible about the PE files and i thought making a parser would be the perfect choice

## What it does

- Reads and parses the DOS header, File header, and Optional header
- Walks the section table
- Parses the Export Directory function names, ordinals, and addresses
- Parses the Import Descriptor table

## Usage
change the filename in `main()` Specificy the location of the exe, run it.
```cpp
File = CreateFileA("ntdll_dump.dll", GENERIC_READ, ...);
```

## Note
you can just pass in argv[1]
```cpp
File = CreateFileA(argv[1], GENERIC_READ, ...);
```
then run it
```
Parse.exe read.exe
```
i was too lazy to Detect if the application is 64 bit or 32 bit so if your dealing with a 64 bit use
```
OptionalHeader64
```
