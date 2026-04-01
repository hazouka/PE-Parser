### PE Parser

## Why

I only built this to learn as much as possible about the PE files and i thought making a parser would be the perfect choice

## What it does

- Reads and parses the DOS header, File header, and Optional header
- Walks the section table
- Parses the Export Directory function names, ordinals, and addresses
- Parses the Import Descriptor table
## Usage

```cpp
main.exe FileToread
```

## Note
i was too lazy to Detect if the application is 64 bit or 32 bit so if your dealing with a 64 bit use
```cpp
OptionalHeader64
```

I will probably be reworking this to use a different way to read the file instead of using the windows api because thats limited to the windows os only
