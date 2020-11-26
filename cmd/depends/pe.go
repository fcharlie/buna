package main

import (
	"fmt"
	"os"

	"github.com/fcharlie/buna/debug/pe"
)

func analyzePeDepends(fd *os.File, p string) int {
	file, err := pe.NewFile(fd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "file not pe file: %v\n", err)
		return 1
	}
	ft, err := file.LookupFunctionTable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "file not pe file: %v\n", err)
		return 1
	}
	m := make(map[string]string)
	for k := range ft.Imports {
		m[k] = ""
	}
	for k := range ft.Delay {
		m[k] = ""
	}

	return 0
}
