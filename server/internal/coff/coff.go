// Package coff parses COFF objects (the format Beacon Object Files use).
//
// The server needs to understand a COFF object for two reasons:
//
//   - the extension store must know whether a blob is a loadable object before
//     it is handed to an implant, and
//   - the operator has to see what a module does before it runs: the symbol
//     table says which functions it exports, which is the cheapest honest
//     description of an in-memory module.
//
// The parser is read-only and defensive: a malformed object is an error, not
// a panic.  Nothing here executes anything.
package coff

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The machine types the loader understands.
const (
	MachineI386  uint16 = 0x014C
	MachineAMD64 uint16 = 0x8664
	MachineARM64 uint16 = 0xAA64
)

// The section characteristics the loader cares about.
const (
	SectionMemRead    = 0x40000000
	SectionMemWrite   = 0x80000000
	SectionMemExecute = 0x20000000
)

// The relocation types of the two architectures the loader supports.
const (
	RelocAMD64Absolute uint16 = 0x0000
	RelocAMD64Addr64   uint16 = 0x0001
	RelocAMD64Addr32   uint16 = 0x0002
	RelocAMD64Addr32NB uint16 = 0x0003
	RelocI386Absolute  uint16 = 0x0000
	RelocI386HighLow   uint16 = 0x0001
)

// MaxObjectSize bounds what the server is willing to look at.  The frame
// limit is smaller, so anything bigger cannot travel to an implant anyway.
const MaxObjectSize = 4 << 20

// MaxSymbols bounds the symbol table the parser keeps in memory.
const MaxSymbols = 4096

// A section of a COFF object.
type Section struct {
	// The name of the section (".text", ".data", ...).
	Name string
	// The virtual size of the section.
	VirtualSize uint32
	// The address of the section in memory.
	VirtualAddress uint32
	// The size of the raw data on disk.
	SizeOfRawData uint32
	// The pointer to the raw data.
	PointerToRawData uint32
	// The characteristics of the section.
	Characteristics uint32
}

// A symbol of a COFF object.
type Symbol struct {
	// The name of the symbol (empty for a section symbol).
	Name string
	// The value of the symbol: an offset for a defined symbol.
	Value uint32
	// The section number the symbol belongs to (-1 for an absolute one).
	SectionNumber int16
	// The type of the symbol.
	Type uint16
	// The number of bytes the symbol occupies.
	SizeOfAux uint8
}

// A relocation of a COFF object.
type Relocation struct {
	// The symbol the relocation refers to.
	SymbolIndex uint32
	// The type of the relocation.
	Type uint16
	// The offset inside the section.
	VirtualAddress uint32
}

// An Object is a parsed COFF object.
type Object struct {
	// The machine the object was built for.
	Machine uint16
	// The number of sections.
	NumberOfSections uint16
	// The timestamp of the object.
	TimeDateStamp uint32
	// The size of the optional header (always zero for a COFF object).
	SizeOfOptionalHeader uint16
	// The characteristics of the object.
	Characteristics uint16
	// The sections of the object.
	Sections []Section
	// The symbols of the object.
	Symbols []Symbol
	// The relocations of the object.
	Relocations []Relocation
}

// ErrNotCOFF is returned when a blob is not a COFF object at all.
var ErrNotCOFF = errors.New("coff: not a COFF object")

// Parse reads a COFF object.
//
// The checks mirror the loader: a header that claims more sections than the
// file holds, a symbol table outside the file or a truncated string table is
// an error, never a panic.
func Parse(data []byte) (*Object, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("coff: the header is truncated (%d bytes)", len(data))
	}
	if len(data) > MaxObjectSize {
		return nil, fmt.Errorf("coff: the object is too large (%d bytes)", len(data))
	}
	magic := binary.LittleEndian.Uint16(data[0:2])
	if magic != 0x014C && magic != 0x8664 && magic != 0xAA64 {
		// A PE image starts with "MZ"; say so instead of failing later.
		if len(data) >= 2 && string(data[0:2]) == "MZ" {
			return nil, errors.New("coff: this is a PE image, not a COFF object")
		}
		return nil, fmt.Errorf("%w: unknown machine 0x%04x", ErrNotCOFF, magic)
	}
	obj := &Object{
		Machine:             magic,
		NumberOfSections:    binary.LittleEndian.Uint16(data[2:4]),
		TimeDateStamp:       binary.LittleEndian.Uint32(data[4:8]),
		PointerToSymbolTable: binary.LittleEndian.Uint32(data[8:12]),
		NumberOfSymbols:     binary.LittleEndian.Uint32(data[12:16]),
		SizeOfOptionalHeader: binary.LittleEndian.Uint16(data[16:18]),
		Characteristics:    binary.LittleEndian.Uint16(data[18:20]),
	}
	if obj.NumberOfSections == 0 || obj.NumberOfSections > 96 {
		return nil, fmt.Errorf("coff: implausible section count %d", obj.NumberOfSections)
	}
	if obj.NumberOfSymbols > MaxSymbols {
		return nil, fmt.Errorf("coff: too many symbols (%d)", obj.NumberOfSymbols)
	}
	sectionTable := 20 + int(obj.SizeOfOptionalHeader)
	if sectionTable+int(obj.NumberOfSections)*40 > len(data) {
		return nil, errors.New("coff: the section table is truncated")
	}
	for i := 0; i < int(obj.NumberOfSections); i++ {
		raw := data[sectionTable+i*40 : sectionTable+i*40+40]
		section := Section{
			VirtualSize:    binary.LittleEndian.Uint32(raw[8:12]),
			VirtualAddress: binary.LittleEndian.Uint32(raw[12:16]),
			SizeOfRawData:  binary.LittleEndian.Uint32(raw[16:20]),
			PointerToRawData: binary.LittleEndian.Uint32(raw[20:24]),
			Characteristics: binary.LittleEndian.Uint32(raw[36:40]),
		}
		if raw[0] != 0 {
			// Long section names live in the string table.
			section.Name = fmt.Sprintf("/%d", binary.LittleEndian.Uint32(raw[0:4]))
		} else {
			end := 0
			for end < 8 && raw[end] != 0 {
				end++
			}
			section.Name = string(raw[:end])
		}
		if section.SizeOfRawData > 0 {
			end := int(section.PointerToRawData) + int(section.SizeOfRawData)
			if int(section.PointerToRawData) > len(data) || end > len(data) {
				return nil, fmt.Errorf("coff: the section %q is truncated", section.Name)
			}
		}
		obj.Sections = append(obj.Sections, section)
	}
	if err := obj.parseSymbols(data); err != nil {
		return nil, err
	}
	return obj, nil
}

// parseSymbols reads the symbol table and the relocations that follow it.
func (o *Object) parseSymbols(data []byte) error {
	if o.PointerToSymbolTable == 0 || o.NumberOfSymbols == 0 {
		return nil
	}
	table := int(o.PointerToSymbolTable)
	count := int(o.NumberOfSymbols)
	if table+count*18 > len(data) {
		return errors.New("coff: the symbol table is truncated")
	}
	// The string table follows the symbol table; the first four bytes hold
	// its size.
	strTable := table + count*18
	strLen := 0
	if strTable+4 <= len(data) {
		strLen = int(binary.LittleEndian.Uint32(data[strTable : strTable+4]))
	}
	readName := func(off int32) string {
		if off > 0 {
			start := strTable + int(off)
			if start < 0 || start >= len(data) {
				return ""
			}
			end := start
			for end < len(data) && data[end] != 0 {
				end++
			}
			return string(data[start:end])
		}
		start := table + int(off)
		if start < 0 || start+8 > len(data) {
			return ""
		}
		end := 0
		for end < 8 && data[start+end] != 0 {
			end++
		}
		return string(data[start : start+end])
	}
	for i := 0; i < count; i++ {
		raw := data[table+i*18 : table+i*18+18]
		symbol := Symbol{
			Value:         binary.LittleEndian.Uint32(raw[8:12]),
			SectionNumber: int16(binary.LittleEndian.Uint16(raw[12:14])),
			Type:          binary.LittleEndian.Uint16(raw[14:16]),
			SizeOfAux:     raw[17],
		}
		symbol.Name = readName(int32(binary.LittleEndian.Uint32(raw[0:4])))
		o.Symbols = append(o.Symbols, symbol)
		i += int(symbol.SizeOfAux)
	}
	// The relocations live right behind the symbol table.
	reloc := strTable
	for len(o.Relocations) < 4096 && reloc+10 <= len(data) {
		virtual := binary.LittleEndian.Uint32(data[reloc : reloc+4])
		symIndex := binary.LittleEndian.Uint32(data[reloc+4 : reloc+8])
		typ := binary.LittleEndian.Uint16(data[reloc+8 : reloc+10])
		if virtual == 0 && symIndex == 0 && typ == 0 {
			break
		}
		o.Relocations = append(o.Relocations, Relocation{
			SymbolIndex:    symIndex,
			Type:           typ,
			VirtualAddress: virtual,
		})
		reloc += 10
	}
	return nil
}

// Entry returns the symbol the loader would call: the first external symbol
// with a non-zero section, preferring one that looks like a main entry point.
func (o *Object) Entry() (Symbol, bool) {
	var fallback Symbol
	found := false
	for _, symbol := range o.Symbols {
		if symbol.SectionNumber <= 0 || symbol.Name == "" {
			continue
		}
		if symbol.Type&0x0020 != 0 { // function
			if symbol.Name == "main" || symbol.Name == "go" || symbol.Name == "DllMain" {
				return symbol, true
			}
			if !found {
				fallback = symbol
				found = true
			}
		}
	}
	return fallback, found
}

// Exports returns the names of the external symbols of the object.
func (o *Object) Exports() []string {
	var out []string
	for _, symbol := range o.Symbols {
		if symbol.Name == "" {
			continue
		}
		if symbol.SectionNumber == 0 {
			continue // absolute: a constant, not a function
		}
		out = append(out, symbol.Name)
	}
	return out
}

// Executable reports whether the object has a section that is marked
// executable and a section that is marked writable.  Both together are the
// shape of a module that wants to patch itself.
func (o *Object) Executable() bool {
	var exec, write bool
	for _, section := range o.Sections {
		if section.Characteristics&SectionMemExecute != 0 {
			exec = true
		}
		if section.Characteristics&SectionMemWrite != 0 {
			write = true
		}
	}
	return exec && write
}

// Describe renders a short, human readable summary of the object.
func (o *Object) Describe() string {
	out := fmt.Sprintf("coff %s, %d section(s), %d symbol(s), %d relocation(s)",
		MachineName(o.Machine), len(o.Sections), len(o.Symbols), len(o.Relocations))
	if entry, ok := o.Entry(); ok {
		out += ", entry " + entry.Name
	}
	return out
}

// Describe renders a short, human readable summary of a raw object.
func Describe(data []byte) string {
	obj, err := Parse(data)
	if err != nil {
		return "unreadable object: " + err.Error()
	}
	return obj.Describe()
}

// MachineName returns the name of a machine type.
func MachineName(machine uint16) string {
	switch machine {
	case MachineI386:
		return "i386"
	case MachineAMD64:
		return "amd64"
	case MachineARM64:
		return "arm64"
	default:
		return fmt.Sprintf("0x%04x", machine)
	}
}
