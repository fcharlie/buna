package pe

import "encoding/binary"

// PE import export table

// ExportedSymbol exported
type ExportedSymbol struct {
	Name          string
	Value         uint32
	SectionNumber uint16
	Type          uint16
	StorageClass  uint8
}

// Function function
type Function struct {
	Name    string
	Index   int
	Ordinal int
}

// Functions functions
type Functions []Function

// FunctionTable function table
type FunctionTable struct {
	Imports map[string]Functions
	Delay   map[string]Functions
	Exports []ExportedSymbol
}

func getFunctionHit(section []byte, start int) uint16 {
	if start < 0 || start-2 > len(section) {
		return 0
	}
	return binary.LittleEndian.Uint16(section[start:])
}

// ImportedSymbols returns the names of all symbols
// referred to by the binary f that are expected to be
// satisfied by other libraries at dynamic load time.
// It does not return weak symbols.
func (f *File) importedSymbols(ft *FunctionTable) error {
	if f.OptionalHeader == nil {
		return nil
	}

	pe64 := f.FileHeader.SizeOfOptionalHeader == OptionalHeader64Size

	// grab the number of data directory entries
	var ddlen uint32
	if pe64 {
		ddlen = f.OptionalHeader.(*OptionalHeader64).NumberOfRvaAndSizes
	} else {
		ddlen = f.OptionalHeader.(*OptionalHeader32).NumberOfRvaAndSizes
	}

	// check that the length of data directory entries is large
	// enough to include the imports directory.
	if ddlen < IMAGE_DIRECTORY_ENTRY_IMPORT+1 {
		return nil
	}

	// grab the import data directory entry
	var idd DataDirectory
	if pe64 {
		idd = f.OptionalHeader.(*OptionalHeader64).DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
	} else {
		idd = f.OptionalHeader.(*OptionalHeader32).DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
	}

	// figure out which section contains the import directory table
	var ds *Section
	ds = nil
	for _, s := range f.Sections {
		if s.VirtualAddress <= idd.VirtualAddress && idd.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			ds = s
			break
		}
	}

	// didn't find a section, so no import libraries were found
	if ds == nil {
		return nil
	}

	d, err := ds.Data()
	if err != nil {
		return nil
	}

	// seek to the virtual address specified in the import data directory
	d = d[idd.VirtualAddress-ds.VirtualAddress:]

	// start decoding the import directory
	var ida []ImportDirectory
	for len(d) >= 20 {
		var dt ImportDirectory
		dt.OriginalFirstThunk = binary.LittleEndian.Uint32(d[0:4])
		dt.TimeDateStamp = binary.LittleEndian.Uint32(d[4:8])
		dt.ForwarderChain = binary.LittleEndian.Uint32(d[8:12])
		dt.Name = binary.LittleEndian.Uint32(d[12:16])
		dt.FirstThunk = binary.LittleEndian.Uint32(d[16:20])
		d = d[20:]
		if dt.OriginalFirstThunk == 0 {
			break
		}
		ida = append(ida, dt)
	}
	// TODO(brainman): this needs to be rewritten
	//  ds.Data() returns contents of section containing import table. Why store in variable called "names"?
	//  Why we are retrieving it second time? We already have it in "d", and it is not modified anywhere.
	//  getString does not extracts a string from symbol string table (as getString doco says).
	//  Why ds.Data() called again and again in the loop?
	//  Needs test before rewrite.
	names, _ := ds.Data()
	for _, dt := range ida {
		dt.dll, _ = getString(names, int(dt.Name-ds.VirtualAddress))
		d, _ = ds.Data()
		// seek to OriginalFirstThunk
		d = d[dt.OriginalFirstThunk-ds.VirtualAddress:]
		var fs Functions
		for len(d) > 0 {
			if pe64 { // 64bit
				va := binary.LittleEndian.Uint64(d[0:8])
				d = d[8:]
				if va == 0 {
					break
				}
				if va&0x8000000000000000 > 0 { // is Ordinal
					// TODO add dynimport ordinal support.
					fs = append(fs, Function{Ordinal: int(va & 0xFFFF)})
				} else {
					fn, _ := getString(names, int(uint32(va)-ds.VirtualAddress+2))
					hit := getFunctionHit(names, int(uint32(va)-ds.VirtualAddress))
					fs = append(fs, Function{Name: fn, Index: int(hit)})
				}
			} else { // 32bit
				va := binary.LittleEndian.Uint32(d[0:4])
				d = d[4:]
				if va == 0 {
					break
				}
				if va&0x80000000 > 0 { // is Ordinal
					// TODO add dynimport ordinal support.
					//ord := va&0x0000FFFF
					fs = append(fs, Function{Ordinal: int(va & 0xFFFF)})
				} else {
					fn, _ := getString(names, int(va-ds.VirtualAddress+2))
					hit := getFunctionHit(names, int(uint32(va)-ds.VirtualAddress))
					fs = append(fs, Function{Name: fn, Index: int(hit)})
				}
			}
		}
		ft.Imports[dt.dll] = fs
	}

	return nil
}

func (f *File) importedDelaySymbols(ft *FunctionTable) error {

	return nil
}

// LookupFunctionTable table
func (f *File) LookupFunctionTable() (*FunctionTable, error) {
	ft := &FunctionTable{
		Imports: make(map[string]Functions),
		Delay:   make(map[string]Functions),
	}
	if err := f.importedSymbols(ft); err != nil {
		return nil, err
	}
	return ft, nil
}
