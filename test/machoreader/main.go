package main

import (
	"fmt"
	"os"

	"github.com/fcharlie/buna/debug/macho"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s pefile\n", os.Args[0])
		os.Exit(1)
	}
	st, err := os.Stat(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable state: %v\n", err)
		os.Exit(1)
	}
	size := st.Size()
	fmt.Fprintf(os.Stderr, "FileSize: %d\n", size)
	fd, err := macho.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable open file: %s %v\n", os.Args[1], err)
		os.Exit(1)
	}
	defer fd.Close()
	if size > int64(fd.OverlayOffset) {
		overlay, err := fd.Overlay()
		if err != nil && err != macho.ErrNoOverlayFound {
			fmt.Fprintf(os.Stderr, "unable lookuo overlay data: %s %v\n", os.Args[1], err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Overlay: %v\n", string(overlay))
	}

}
