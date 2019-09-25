// Gatsby is a cross platform PE file analasis tool
// Written by Tristan Messner(@wolfshirtz)
package main

import (
	"debug/pe"
	"errors"
	"flag"
	"fmt"
	"reflect"
    "github.com/knightsc/gapstone"
)

func SectionsNames(f *pe.File) []string {
	var return_array []string
	// Loop over the sections to get the names of the sections
	for index, _ := range f.Sections {
		return_array = append(return_array, f.Sections[index].SectionHeader.Name)
	}
	return return_array
}

func CapDisasm(f *pe.Section){
        //Reads section data of .text
        //Then runs it through the capstone decompiler
        //The gapstone frontend for capstones docs and examples can be
        //Found at https://github.com/bnagy/gapstone
        //CS_ARCH_X86 supports both x86 and x64 disasmebly
        engine, err := gapstone.New(gapstone.CS_ARCH_X86, gapstone.CS_MODE_64)
        if err != nil{
                fmt.Println(err)
                return
        }
        code, err := f.Data()
        if err != nil{
                fmt.Println(err)
                return
        }
        //The disassemly "magic"
        //Addr is just used to make the decompile more pretty
        Addr := f.SectionHeader.VirtualAddress
        ins, err := engine.Disasm(
                code,
                uint64(Addr),
                0)
        if err != nil{
                fmt.Println(err)
                return
        }
        for _, insn := range ins{
                fmt.Printf("0x%x [> %s %s\n", insn.Address, insn.Mnemonic, insn.OpStr)
        }

}


func dump_section(f *pe.Section) {
	// Reads section data into a byte array
	// then converts to a string and prints that data
	bytes, err := f.Data()
	if err != nil {
		fmt.Println("Cannot dump data")
	} else {
		fmt.Println(string(bytes[:]))
	}
}

func ShowSymbols(f *pe.File) {
	// Finds the imported symbols of a binary and prints them with
	// pprint_array
	syms, err := f.ImportedSymbols()
	if err != nil {
		fmt.Println("Cannot get Imported Symbols")
		return
	}
	pprint_array(syms, "")
}

func ShowCoffNames(f *pe.File) ([]string, error) {
	var return_array []string
	var _err error
	for index, _ := range f.COFFSymbols {
		str, err := f.COFFSymbols[index].FullName(f.StringTable)
		if err != nil {
			_err = err
			fmt.Println(err)
		}
		return_array = append(return_array, str)
	}
	return return_array, _err
}

func show_file(f *pe.File) error {
	// Determines the type of the interface
	// For optionalheader
	// Then assertates to that type
	var _err error
	typ := reflect.TypeOf(f.OptionalHeader)
	if typ.String() == "*pe.OptionalHeader32" {
		header := f.OptionalHeader.(*pe.OptionalHeader32)
		print_file_info(header.AddressOfEntryPoint, header.BaseOfCode, header.ImageBase)
	} else {
		if typ.String() == "*pe.OptionalHeader64" {
			header := f.OptionalHeader.(*pe.OptionalHeader64)
			print_file_info(header.AddressOfEntryPoint, header.BaseOfCode, header.ImageBase)
		} else {
			_err = errors.New("issue setting up header type")
			return _err
		}
	}
	return _err
}
func print_file_info(entry_point interface{}, basecode interface{}, imagebase interface{}) {
	//cleaner alternative to writing out the print statements for each if statement in show_file
	pprint(fmt.Sprintf("0x%x", entry_point), "Entry point:")
	pprint(fmt.Sprintf("0x%x", basecode), "Base of code:")
	pprint(fmt.Sprintf("0x%x", imagebase), "Image base:")
}

func pprint_array(f []string, prefix string) {
	// Call the function like so for no prefix
	// pprint_array(str_array,"")
	for index, _ := range f {
		pprint(f[index], prefix)
	}
}

func pprint(str string, prefix string) {
	fmt.Print(prefix)
	fmt.Println(str)
}

func main() {
	// Program flags
	var file string
	var Display_Sections bool
	var Display_ImportedSyms bool
	var Display_Coff bool
	var Display_File bool
	var Display_Section_Dump string
    var Display_Dis bool

	// Parse program flags
	flag.StringVar(&file, "FileName", "", "pe file to open")
	flag.BoolVar(&Display_Sections, "ShowSections", false, "Shows the names of present sections of the binary")
	flag.BoolVar(&Display_ImportedSyms, "ImportedSymbols", false, "Shows the imported symbols of the binary")
	flag.BoolVar(&Display_Coff, "ShowCoff", false, "Shows the names of symbols with names greater than 8 characters")
	flag.BoolVar(&Display_File, "ShowFile", false, "Shows details about the file")
    flag.BoolVar(&Display_Dis, "DisAsm", false, "Runs a capstone disassembler on .text section")
	flag.StringVar(&Display_Section_Dump, "DumpSection", "", "Section to dump")
	flag.Parse()

	if file == "" {
		fmt.Println("Use -FileName to open a file")
		return
	}
	pe_file, err := pe.Open(file)
	if err != nil {
		fmt.Println("Cannot open file")
		fmt.Println(err)
		return
	}
	if Display_Sections == true {
		Sections := SectionsNames(pe_file)
		pprint_array(Sections, "Section:")
	}
	if Display_ImportedSyms == true {
		ShowSymbols(pe_file)
	}
	if Display_Coff == true {
		coff, err := ShowCoffNames(pe_file)
		if err != nil {
			fmt.Println(err)
			return
		}
		pprint_array(coff, "CoffSym:")
	}
	if Display_File == true {
		err := show_file(pe_file)
		if err != nil {
			fmt.Println(err)
		}
	}

	if Display_Section_Dump != "" {
		sec := pe_file.Section(Display_Section_Dump)
		if sec == nil {
			fmt.Println("Section dose not exist")
			return
		}
		dump_section(sec)
	}
    if Display_Dis == true{
        CapDisasm(pe_file.Section(".text"))
    }
	pe_file.Close()
}
