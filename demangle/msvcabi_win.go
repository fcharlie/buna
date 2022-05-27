//go:build windows

package demangle

import (
	"syscall"
	"unsafe"
)

// load UnDecorateSymbolName

var (
	dbghelp               = syscall.NewLazyDLL("Dbghelp")
	pUnDecorateSymbolName = dbghelp.NewProc("UnDecorateSymbolName")
)

/*
BytePtrFromString todo
DWORD IMAGEAPI UnDecorateSymbolName(
  PCSTR name,
  PSTR  outputString,
  DWORD maxStringLength,
  DWORD flags
);
*/
func BytePtrFromString(s string) *byte {
	a, _ := syscall.BytePtrFromString(s)
	return a
}

// MsvcFilter filter
func MsvcFilter(name string) string {
	var data [1024]byte
	nlen, _, _ := pUnDecorateSymbolName.Call(
		uintptr(unsafe.Pointer(BytePtrFromString(name))),
		uintptr(unsafe.Pointer(&data)),
		uintptr(1024),
		uintptr(0),
	)
	if nlen == 0 {
		return name
	}
	return string(data[0:nlen])
}
