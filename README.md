# Buna

The software package provides various executable file format analysis capabilities

+   PE/COFF
+   ELF
+   Mach-O

This package is transplanted from [debug](https://github.com/golang/go/tree/master/src/debug) in the Golang source code directory. Currently, it supports parsing ARM64 PE files, as well as parsing export tables and delayed import tables.

This package also ported [ianlancetaylor/demangle](https://github.com/ianlancetaylor/demangle), which can demangle MSVC ABI C++ functions in Windows. 

## Docs

[https://pkg.go.dev/github.com/fcharlie/buna](https://pkg.go.dev/github.com/fcharlie/buna)

## Usage

```shell
go get github.com/fcharlie/buna
```

Example:

```go
package main

import (
	"fmt"
	"os"

	"github.com/fcharlie/buna/debug/pe"
	"github.com/fcharlie/buna/demangle"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s pefile\n", os.Args[0])
		os.Exit(1)
	}
	fd, err := pe.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable open file: %s %v\n", os.Args[1], err)
		os.Exit(1)
	}
	defer fd.Close()
	ft, err := fd.LookupFunctionTable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable LookupExports: %s %v\n", os.Args[1], err)
		os.Exit(1)
	}
	for dll, ims := range ft.Imports {
		fmt.Fprintf(os.Stderr, "\x1b[33mDllName: %s\x1b[0m\n", dll)
		for _, n := range ims {
			if n.Ordinal == 0 {
				fmt.Fprintf(os.Stderr, "%s %d\n", n.Name, n.Index)
				continue
			}
			fmt.Fprintf(os.Stderr, "Ordinal%d (Ordinal %d)\n", n.Ordinal, n.Ordinal)
		}
	}
	for dll, ims := range ft.Imports {
		fmt.Fprintf(os.Stderr, "\x1b[34mDelay DllName: %s\x1b[0m\n", dll)
		for _, n := range ims {
			if n.Ordinal == 0 {
				fmt.Fprintf(os.Stderr, "(Delay) %s %d\n", n.Name, n.Index)
				continue
			}
			fmt.Fprintf(os.Stderr, "(Delay) Ordinal%d (Ordinal %d)\n", n.Ordinal, n.Ordinal)
		}
	}
	for _, d := range ft.Exports {
		fmt.Fprintf(os.Stderr, "\x1b[35mE %5d %08X %s  (Hint: %d)\x1b[0m\n", d.Ordinal, d.Address, demangle.Demangle(d.Name), d.Hint)
	}
}

```
