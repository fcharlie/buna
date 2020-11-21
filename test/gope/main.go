package main

import (
	"fmt"
	"os"

	"github.com/fcharlie/buna/debug/pe"
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
	exports, err := fd.LookupExports()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable LookupExports: %s %v\n", os.Args[1], err)
		os.Exit(1)
	}
	for _, d := range exports {
		fmt.Fprintf(os.Stderr, "\x1b[35mE %5d %08X %s  (Hint: %d)\x1b[0m\n", d.Ordinal, d.Address, d.Name, d.Hint)
	}
}
