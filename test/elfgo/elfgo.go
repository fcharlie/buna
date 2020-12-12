package main

import (
	"fmt"
	"os"

	"github.com/fcharlie/buna/debug/elf"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s elf\n", os.Args[0])
		os.Exit(1)
	}
	file, err := elf.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "open file: %s elf error: %v\n", os.Args[0], err)
		os.Exit(1)
	}
	defer file.Close()
	for _, s := range file.Sections {
		fmt.Fprintf(os.Stderr, "%s: %08x %d %d %d\n", s.Name, s.Addr, s.Size, s.Entsize, s.Flags)
	}
	libs, err := file.ImportedLibraries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ImportedLibraries: %s elf error: %v\n", os.Args[0], err)
		os.Exit(1)
	}
	for _, l := range libs {
		fmt.Fprintf(os.Stderr, "need: %s\n", l)
	}
	if symbols, err := file.Symbols(); err == nil {
		fmt.Fprintf(os.Stderr, "Symbols:\n")
		for _, s := range symbols {
			fmt.Fprintf(os.Stderr, "%s\n", s.Name)
		}
	}

	if symbols, err := file.DynamicSymbols(); err == nil {
		fmt.Fprintf(os.Stderr, "Dynamic Symbols:\n")
		for _, s := range symbols {
			fmt.Fprintf(os.Stderr, "%s (%s@%s)\n", s.Name, s.Library, s.Version)
		}
	}

}
