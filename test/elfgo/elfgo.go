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
}
