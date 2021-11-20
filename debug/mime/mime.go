package mime

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/fcharlie/buna/debug/macho"
)

// BinType bintype
type BinType int

// defined
const (
	PE          BinType = 0x1
	ELF         BinType = 0x2
	MACHO       BinType = 0x4
	Shared      BinType = 0x10000 //shared object
	Executable  BinType = 0x20000
	Relocatable BinType = 0x40000
	CoreDump    BinType = 0x80000
)

// IsElf is elf file
func (b BinType) IsElf() bool {
	return b&ELF != 0
}

// IsPE is pe file
func (b BinType) IsPE() bool {
	return b&PE != 0
}

// IsMachO is macho file
func (b BinType) IsMachO() bool {
	return b&MACHO != 0
}

// Mime
const (
	PeMime             = "application/vnd.microsoft.portable-executable"
	ElfMime            = "application/x-elf"
	ElfRelocatableMime = "application/x-relocatable"
	ElfExecutableMime  = "application/x-executable"
	ElfSharedLibMime   = "application/x-sharedlib"
	ElfCoreDumpMime    = "application/x-coredump"
	MachoMime          = "application/x-mach-binary"
)

// Thanks https://github.com/gabriel-vasile/mimetype/blob/master/internal/matchers/binary.go

// Java bytecode and Mach-O binaries share the same magic number.
// More info here https://github.com/threatstack/libmagic/blob/master/magic/Magdir/cafebabe
func classOrMachOFat(in []byte) bool {
	// There should be at least 8 bytes for both of them because the only way to
	// quickly distinguish them is by comparing byte at position 7
	if len(in) < 8 {
		return false
	}

	return bytes.HasPrefix(in, []byte{0xCA, 0xFE, 0xBA, 0xBE})
}

// Class matches a java class file.
func Class(in []byte) bool {
	return classOrMachOFat(in) && in[7] > 30
}

// MachO matches Mach-O binaries format.
func MachO(in []byte) bool {
	if classOrMachOFat(in) && in[7] < 20 {
		return true
	}

	if len(in) < 4 {
		return false
	}

	be := binary.BigEndian.Uint32(in)
	le := binary.LittleEndian.Uint32(in)

	return be == macho.Magic32 || le == macho.Magic32 || be == macho.Magic64 || le == macho.Magic64
}

// Exe matches a Windows/DOS executable file.
func Exe(in []byte) bool {
	return bytes.HasPrefix(in, []byte{0x4D, 0x5A})
}

// Elf matches an Executable and Linkable Format file.
func Elf(in []byte) bool {
	return bytes.HasPrefix(in, []byte{0x7F, 0x45, 0x4C, 0x46})
}

// ElfObj matches an object file.
func ElfObj(in []byte) bool {
	return len(in) > 17 && ((in[16] == 0x01 && in[17] == 0x00) ||
		(in[16] == 0x00 && in[17] == 0x01))
}

// ElfExe matches an executable file.
func ElfExe(in []byte) bool {
	return len(in) > 17 && ((in[16] == 0x02 && in[17] == 0x00) ||
		(in[16] == 0x00 && in[17] == 0x02))
}

// ElfLib matches a shared library file.
func ElfLib(in []byte) bool {
	return len(in) > 17 && ((in[16] == 0x03 && in[17] == 0x00) ||
		(in[16] == 0x00 && in[17] == 0x03))
}

// ElfDump matches a core dump file.
func ElfDump(in []byte) bool {
	return len(in) > 17 && ((in[16] == 0x04 && in[17] == 0x00) ||
		(in[16] == 0x00 && in[17] == 0x04))
}

// Detect detect header
func Detect(b []byte) (string, BinType, error) {
	if Exe(b) {
		return PeMime, PE, nil
	}
	if Elf(b) {
		if ElfObj(b) {
			return ElfRelocatableMime, ELF | Relocatable, nil
		}
		if ElfExe(b) {
			return ElfExecutableMime, ELF | Executable, nil
		}
		if ElfLib(b) {
			return ElfSharedLibMime, ELF | Shared, nil
		}
		if ElfDump(b) {
			return ElfCoreDumpMime, ELF | CoreDump, nil
		}
		return ElfMime, ELF, nil
	}
	if MachO(b) {
		return MachoMime, MACHO, nil
	}

	return "", 0, errors.New("unsupport mime")
}
