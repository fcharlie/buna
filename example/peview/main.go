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
		if len(d.Name) == 0 {
			if len(d.ForwardName) != 0 {
				fmt.Fprintf(os.Stderr, "\x1b[35mE %5d %08X (unnamed) (Hint: %d) --> %s\x1b[0m\n", d.Ordinal, d.Address, d.Hint, d.ForwardName)
				continue
			}
			fmt.Fprintf(os.Stderr, "\x1b[35mE %5d %08X (unnamed) (Hint: %d)\x1b[0m\n", d.Ordinal, d.Address, d.Hint)
			continue
		}
		if len(d.ForwardName) != 0 {
			fmt.Fprintf(os.Stderr, "\x1b[35mE %5d %08X %s  (Hint: %d) --> %s\x1b[0m\n", d.Ordinal, d.Address, demangle.Demangle(d.Name), d.Hint, d.ForwardName)
			continue
		}
		fmt.Fprintf(os.Stderr, "\x1b[35mE %5d %08X %s  (Hint: %d)\x1b[0m\n", d.Ordinal, d.Address, demangle.Demangle(d.Name), d.Hint)
	}
	fmt.Fprintf(os.Stderr, "Overlay Length: %d\n", fd.OverlayLength())
	// overlay, err := fd.Overlay()
	// if err != nil && err != pe.ErrNoOverlayFound {
	// 	fmt.Fprintf(os.Stderr, "unable detect overlay data: %s %v\n", os.Args[1], err)
	// 	os.Exit(1)
	// }
	// fmt.Fprintf(os.Stderr, "Overlay: %v\n", string(overlay))
}
