#!/usr/bin/env python3
# Reconstruct section table for a binary.
# Robert Xiao <nneonneo@gmail.com>, May 27 2014

import struct
from ctypes import *
import mmap
import enum

Elf_Byte = c_uint8
Elf32_Half = c_uint16
Elf32_Word = c_uint32
Elf32_Addr = Elf32_Off = c_uint32

class PT(enum.IntEnum):
    NULL = 0	# Program header table entry unused
    LOAD = 1	# Loadable program segment
    DYNAMIC = 2	# Dynamic linking information
    INTERP = 3	# Program interpreter
    NOTE = 4	# Auxiliary information
    SHLIB = 5	# Reserved, unspecified semantics
    PHDR = 6	# Entry for header table itself
    TLS = 7	# TLS initialisation image
    ARM_EXIDX = 0x70000001

class PF(enum.IntEnum):
    R = 0x4	# Segment is readable
    W = 0x2	# Segment is writable
    X = 0x1	# Segment is executable

class DT(enum.IntEnum):
    NULL = 0	# Marks end of dynamic array
    NEEDED = 1	# Name of needed library (DT_STRTAB offset)
    PLTRELSZ = 2	# Size, in bytes, of relocations in PLT
    PLTGOT = 3	# Address of PLT and/or GOT
    HASH = 4	# Address of symbol hash table
    STRTAB = 5	# Address of string table
    SYMTAB = 6	# Address of symbol table
    RELA = 7	# Address of Rela relocation table
    RELASZ = 8	# Size, in bytes, of DT_RELA table
    RELAENT = 9	# Size, in bytes, of one DT_RELA entry
    STRSZ = 10	# Size, in bytes, of DT_STRTAB table
    SYMENT = 11	# Size, in bytes, of one DT_SYMTAB entry
    INIT = 12	# Address of initialization function
    FINI = 13	# Address of termination function
    SONAME = 14	# Shared object name (DT_STRTAB offset)
    RPATH = 15	# Library search path (DT_STRTAB offset)
    SYMBOLIC = 16	# Start symbol search within local object
    REL = 17	# Address of Rel relocation table
    RELSZ = 18	# Size, in bytes, of DT_REL table
    RELENT = 19	# Size, in bytes, of one DT_REL entry
    PLTREL = 20	# Type of PLT relocation entries
    DEBUG = 21	# Used for debugging; unspecified
    TEXTREL = 22	# Relocations might modify non-writable seg
    JMPREL = 23	# Address of relocations associated with PLT
    BIND_NOW = 24	# Process all relocations at load-time
    INIT_ARRAY = 25	# Address of initialization function array
    FINI_ARRAY = 26	# Size, in bytes, of DT_INIT_ARRAY array
    INIT_ARRAYSZ = 27	# Address of termination function array
    FINI_ARRAYSZ = 28	# /* Size, in bytes, of DT_FINI_ARRAY array*/

    GNU_HASH = 0x6ffffef5

    VERSYM = 0x6ffffff0	# Symbol versions
    FLAGS_1 = 0x6ffffffb	# ELF dynamic flags
    VERDEF = 0x6ffffffc	# Versions defined by file
    VERDEFNUM = 0x6ffffffd	# Number of versions defined by file
    VERNEED = 0x6ffffffe	# Versions needed by file
    VERNEEDNUM = 0x6fffffff	# Number of versions needed by file

class SHT(enum.IntEnum):
    NULL = 0	# Section header table entry unused
    PROGBITS = 1	# Program information
    SYMTAB = 2	# Symbol table
    STRTAB = 3	# String table
    RELA = 4	# Relocation information w/ addend
    HASH = 5	# Symbol hash table
    DYNAMIC = 6	# Dynamic linking information
    NOTE = 7	# Auxiliary information
    NOBITS = 8	# No space allocated in file image
    REL = 9	# Relocation information w/o addend
    SHLIB = 10	# Reserved, unspecified semantics
    DYNSYM = 11	# Symbol table for dynamic linker
    INIT_ARRAY = 14	# Initialization function pointers
    FINI_ARRAY = 15	# Termination function pointers
    PREINIT_ARRAY = 16	# Pre-initialization function ptrs
    GROUP = 17	# Section group
    SYMTAB_SHNDX = 18	# Section indexes (see SHN_XINDEX)

    QNXREL = 0x60000000
    GNU_HASH = 0x6ffffff6	# GNU style symbol hash table

class SHF(enum.IntEnum):
    WRITE = 0x00000001	# Contains writable data
    ALLOC = 0x00000002	# Occupies memory
    EXECINSTR = 0x00000004	# Contains executable insns
    MERGE = 0x00000010	# Might be merged
    STRINGS = 0x00000020	# Contains nul terminated strings
    INFO_LINK = 0x00000040	# "sh_info" contains SHT index
    LINK_ORDER = 0x00000080	# Preserve order after combining
    OS_NONCONFORMING = 0x00000100	# OS specific handling required
    GROUP = 0x00000200	# Is member of a group
    TLS = 0x00000400	# Holds thread-local data
    MASKOS = 0x0ff00000	# Operating system specific values
    MASKPROC = 0xf0000000	# Processor-specific values
    ORDERED = 0x40000000	# Ordering requirement (Solaris)
    EXCLUDE = 0x80000000	# /* Excluded unless unles ref/alloc

class Elf32_Ehdr(Structure):
    _fields_ = [
        ('e_ident', c_char * 16),   # Id bytes
        ('e_type', Elf32_Half),     # file type
        ('e_machine', Elf32_Half),  # machine type
        ('e_version', Elf32_Word),  # version number
        ('e_entry', Elf32_Addr),    # entry point
        ('e_phoff', Elf32_Off),     # Program hdr offset
        ('e_shoff', Elf32_Off),     # Section hdr offset
        ('e_flags', Elf32_Word),    # Processor flags
        ('e_ehsize', Elf32_Half),   # sizeof ehdr
        ('e_phentsize', Elf32_Half),# Program header entry size
        ('e_phnum', Elf32_Half),    # Number of program headers
        ('e_shentsize', Elf32_Half),# Section header entry size
        ('e_shnum', Elf32_Half),    # Number of section headers
        ('e_shstrndx', Elf32_Half), # String table index
    ]

class Elf32_Phdr(Structure):
    _fields_ = [
        ('p_type', Elf32_Word),     # entry type
        ('p_offset', Elf32_Off),    # offset
        ('p_vaddr', Elf32_Addr),    # virtual address
        ('p_paddr', Elf32_Addr),    # physical address
        ('p_filesz', Elf32_Word),   # file size
        ('p_memsz', Elf32_Word),    # memory size
        ('p_flags', Elf32_Word),    # flags
        ('p_align', Elf32_Word),    # memory & file alignment
    ]

class Elf32_Shdr(Structure):
    _fields_ = [
        ('sh_name', Elf32_Word),    # section name (.shstrtab index)
        ('sh_type', Elf32_Word),    # section type
        ('sh_flags', Elf32_Word),   # section flags
        ('sh_addr', Elf32_Addr),    # virtual address
        ('sh_offset', Elf32_Off),   # file offset
        ('sh_size', Elf32_Word),    # section size
        ('sh_link', Elf32_Word),    # link to another
        ('sh_info', Elf32_Word),    # misc info
        ('sh_addralign', Elf32_Word),   # memory alignment
        ('sh_entsize', Elf32_Word), # table entry size
    ]

class Elf32_Sym(Structure):
    _fields_ = [
        ('st_name', Elf32_Word),	# Symbol name (.strtab index)
        ('st_value', Elf32_Word),	# value of symbol
        ('st_size', Elf32_Word),	# size of symbol
        ('st_info', Elf_Byte),	# type / binding attrs
        ('st_other', Elf_Byte),	# unused
        ('st_shndx', Elf32_Half),	# section index of symbol
    ]

def print_struct(s):
    for name, _ in type(s)._fields_:
        print('  %s = %s' % (name, getattr(s, name)))

def readstruct(fmt, m, pos):
    return struct.unpack(fmt, m[pos:pos+struct.calcsize(fmt)].tobytes())

def remove_intervals(intervals, segments):
    ''' Remove one list of intervals from another. '''
    for ss, se in segments:
        new_intervals = []
        for ins, ine in intervals:
            if ins >= se or ine <= ss:
                # ss..se..ins..ine
                # or ins..ine..ss..se
                new_intervals.append((ins, ine))
            elif ss <= ins:
                if se < ine:
                    new_intervals.append((se, ine))
                else:
                    # interval deleted
                    continue
            else:
                if se < ine:
                    new_intervals.append((ins, ss))
                    new_intervals.append((se, ine))
                else:
                    new_intervals.append((ins, ss))
        intervals = new_intervals
    return intervals

def reconstruct_sections(m, end):
    ''' Reconstruct the sections in an mmap'd file. '''

    m = memoryview(m)

    # Page-align end
    end = (end + 4095) & ~4095

    # Load ELF header
    ehdr = Elf32_Ehdr.from_buffer(m)

    # Load program headers
    phoff = ehdr.e_phoff
    phnum = ehdr.e_phnum
    phsize = ehdr.e_phentsize
    phdrs = [Elf32_Phdr.from_buffer(m[phoff+i*phsize:]) for i in range(phnum)]

    p_dyn = None
    p_loads = []

    for i, phdr in enumerate(phdrs):
        if phdr.p_type == PT.DYNAMIC:
            p_dyn = phdr
        elif phdr.p_type == PT.LOAD:
            p_loads.append(phdr)

    def phdr_from_addr(addr):
        for phdr in p_loads:
            if phdr.p_vaddr <= addr < phdr.p_vaddr+phdr.p_memsz:
                return phdr
        raise ValueError("addr {:08x} not contained within a phdr!".format(addr))

    def addr_to_offset(addr):
        phdr = phdr_from_addr(addr)
        return addr - phdr.p_vaddr + phdr.p_offset

    # Set up sections
    sections = [] # [(name, Shdr)]
    sections.append(('', Elf32_Shdr(sh_type=SHT.NULL))) # null header

    if p_dyn is not None:
        # Load DYNAMIC section data
        dynlist = []
        pos = p_dyn.p_offset
        while True:
            tag, data = readstruct('<II', m, pos)
            pos += 8
            dynlist.append((tag, data))
            if tag == 0:
                break

        dynamic = dict(dynlist)

        sections.append(('.dynamic', Elf32_Shdr(
            sh_type=SHT.DYNAMIC,
            sh_flags=SHF.WRITE | SHF.ALLOC,
            sh_addr=p_dyn.p_vaddr,
            sh_offset=p_dyn.p_offset,
            sh_size=p_dyn.p_memsz,
            sh_addralign=4,
            sh_entsize=8,
        )))

        # .dynsym/.dynstr
        symaddr = dynamic[DT.SYMTAB]
        straddr = dynamic[DT.STRTAB]
        if straddr <= symaddr:
            print("Warning: cannot determine size of symtab!")
            symsize = 0
        else:
            symsize = straddr - symaddr

        dynsym_nr = len(sections)
        sections.append(('.dynsym', Elf32_Shdr(
            sh_type=SHT.DYNSYM,
            sh_flags=SHF.ALLOC,
            sh_addr=symaddr,
            sh_offset=addr_to_offset(symaddr),
            sh_size=symsize,
            sh_addralign=4,
            sh_link=len(sections)+1, # link to .dynstr
            sh_entsize=dynamic.get(DT.SYMENT, sizeof(Elf32_Sym))
        )))
        sections.append(('.dynstr', Elf32_Shdr(
            sh_type=SHT.STRTAB,
            sh_flags=SHF.ALLOC,
            sh_addr=straddr,
            sh_offset=addr_to_offset(straddr),
            sh_size=dynamic.get(DT.STRSZ, 0),
            sh_addralign=1)))

        # .hash/.gnu.hash
        if DT.GNU_HASH in dynamic:
            addr = dynamic[DT.GNU_HASH]
            offs = addr_to_offset(addr)
            nbuckets, symndx, maskwords, shift2 = readstruct('<IIII', m, offs)
            ### XXX Don't know nsyms?! Should be (nsyms - symndx) * 4 size
            size = 16 + maskwords*4 + nbuckets*4 + (symsize//16 - symndx)*4
            sections.append(('.gnu.hash', Elf32_Shdr(
                sh_type=SHT.GNU_HASH,
                sh_flags=SHF.ALLOC,
                sh_addr=addr,
                sh_offset=offs,
                sh_size=size,
                sh_addralign=4,
                sh_link=dynsym_nr,
                sh_entsize=4,
            )))

        elif DT.HASH in dynamic:
            addr = dynamic[DT.HASH]
            offs = addr_to_offset(addr)
            nbuckets, nchains = readstruct('<II', m, offs)
            size = 8 + nbuckets*4 + nchains*4
            sections.append(('.hash', Elf32_Shdr(
                sh_type=SHT.HASH,
                sh_flags=SHF.ALLOC,
                sh_addr=dynamic[DT.HASH],
                sh_offset=offs,
                sh_size = size,
                sh_addralign=4,
                sh_entsize=4,
            )))

        else:
            print("Warning: no HASH in DYNAMIC section?")

        # .rel[a].dyn/.rel[a].plt
        if dynamic[DT.PLTREL] == DT.RELA:
            sections.append(('.rela.dyn', Elf32_Shdr(
                sh_type=SHT.REL,
                sh_flags=SHF.ALLOC,
                sh_addr=dynamic[DT.RELA],
                sh_offset=addr_to_offset(dynamic[DT.RELA]),
                sh_size=dynamic[DT.RELASZ],
                sh_addralign=4,
                sh_link=dynsym_nr,
                sh_entsize=dynamic.get(DT.RELAENT, 8),
            )))

            sections.append(('.rela.plt', Elf32_Shdr(
                sh_type=SHT.REL,
                sh_flags=SHF.ALLOC,
                sh_addr=dynamic[DT.JMPREL],
                sh_offset=addr_to_offset(dynamic[DT.JMPREL]),
                sh_size=dynamic[DT.PLTRELSZ],
                sh_addralign=4,
                sh_link=dynsym_nr,
                sh_entsize=dynamic.get(DT.RELENT, 8),
            )))
        elif dynamic[DT.PLTREL] == DT.REL:
            sections.append(('.rel.dyn', Elf32_Shdr(
                sh_type=SHT.REL,
                sh_flags=SHF.ALLOC,
                sh_addr=dynamic[DT.REL],
                sh_offset=addr_to_offset(dynamic[DT.REL]),
                sh_size=dynamic[DT.RELSZ],
                sh_addralign=4,
                sh_link=dynsym_nr,
                sh_entsize=dynamic.get(DT.RELENT, 8),
            )))

            sections.append(('.rel.plt', Elf32_Shdr(
                sh_type=SHT.REL,
                sh_flags=SHF.ALLOC,
                sh_addr=dynamic[DT.JMPREL],
                sh_offset=addr_to_offset(dynamic[DT.JMPREL]),
                sh_size=dynamic[DT.PLTRELSZ],
                sh_addralign=4,
                sh_link=dynsym_nr,
                sh_entsize=dynamic.get(DT.RELENT, 8),
            )))
        else:
            raise Exception("unknown PLTREL value {}".format(dynamic[DT.PLTREL]))

        # .got (TODO)

        # .init/.init_array/.fini/.fini_array
        # We don't bother with .init or .fini.
        if DT.INIT_ARRAY in dynamic:
            sections.append(('.init_array', Elf32_Shdr(
                sh_type=SHT.INIT_ARRAY,
                sh_flags=SHF.WRITE | SHF.ALLOC,
                sh_addr=dynamic[DT.INIT_ARRAY],
                sh_offset=addr_to_offset(dynamic[DT.INIT_ARRAY]),
                sh_size=dynamic[DT.INIT_ARRAYSZ],
                sh_addralign=4,
            )))

        if DT.FINI_ARRAY in dynamic:
            sections.append(('.fini_array', Elf32_Shdr(
                sh_type=SHT.FINI_ARRAY,
                sh_flags=SHF.WRITE | SHF.ALLOC,
                sh_addr=dynamic[DT.FINI_ARRAY],
                sh_offset=addr_to_offset(dynamic[DT.FINI_ARRAY]),
                sh_size=dynamic[DT.FINI_ARRAYSZ],
                sh_addralign=4,
            )))

    # .text/.data/.rodata/.bss/.other
    section_ivals = [(section.sh_addr, section.sh_addr + section.sh_size) for name, section in sections]
    text_ivals = []
    data_ivals = []
    bss_ivals = []
    robss_ivals = [] # for lack of a better term

    for phdr in p_loads:
        if phdr.p_flags & PF.W:
            if phdr.p_filesz:
                data_ivals.append((phdr.p_vaddr, phdr.p_vaddr+phdr.p_filesz))
            if phdr.p_memsz > phdr.p_filesz:
                bss_ivals.append((phdr.p_vaddr+phdr.p_filesz, phdr.p_vaddr+phdr.p_memsz))
        else:
            if phdr.p_filesz:
                text_ivals.append((phdr.p_vaddr, phdr.p_vaddr+phdr.p_filesz))
            if phdr.p_memsz > phdr.p_filesz:
                robss_ivals.append((phdr.p_vaddr+phdr.p_filesz, phdr.p_vaddr+phdr.p_memsz))

    text_ivals = remove_intervals(text_ivals, section_ivals)
    data_ivals = remove_intervals(data_ivals, section_ivals)
    bss_ivals = remove_intervals(bss_ivals, section_ivals)
    robss_ivals = remove_intervals(robss_ivals, section_ivals)

    def create_sections(ivals, prefix, type, flags):
        tmp_sections = []

        max_len = 0
        max_i = 0
        for i, (ins, ine) in enumerate(ivals):
            tmp_sections.append((prefix + '.' + str(i), Elf32_Shdr(
                sh_type=type,
                sh_flags=flags,
                sh_addr=ins,
                sh_offset=addr_to_offset(ins),
                sh_size=ine-ins,
                sh_addralign=1,
            )))
            if ine-ins > max_len:
                max_len = ine-ins
                max_i = i
        for i, (name, section) in enumerate(tmp_sections):
            if i == max_i:
                sections.append((prefix, section))
            else:
                sections.append((name, section))

    create_sections(text_ivals, '.text', SHT.PROGBITS, SHF.ALLOC | SHF.EXECINSTR)
    create_sections(data_ivals, '.data', SHT.PROGBITS, SHF.ALLOC | SHF.WRITE)
    create_sections(bss_ivals, '.bss', SHT.NOBITS, SHF.ALLOC | SHF.WRITE)
    create_sections(robss_ivals, '.robss', SHT.NOBITS, SHF.ALLOC)

    if p_dyn is not None:
        # Fixup section indices in symtab
        symoffs = addr_to_offset(symaddr)
        symbols = (Elf32_Sym * (symsize//sizeof(Elf32_Sym))).from_buffer(m[symoffs:symoffs+symsize])
        for symi, sym in enumerate(symbols):
            if sym.st_value != 0 and 0 < sym.st_shndx < 0xff00:
                for i, (name, section) in enumerate(sections):
                    if section.sh_addr <= sym.st_value <= section.sh_addr + section.sh_size:
                        sym.st_shndx = i
                        break
                else:
                    print("section for symbol {} (value={:08x}, shndx={}) not found!".format(symi, sym.st_value, sym.st_shndx))

    # Write the strtab
    strtab = Elf32_Shdr(sh_type=SHT.STRTAB, sh_addralign=1)
    sections.append(('.strtab', strtab))

    strs = []
    strpos = 0
    for name, section in sections:
        section.sh_name = strpos
        strs.append(name + '\0')
        strpos += len(name) + 1

    strtab.sh_offset = end + len(sections) * sizeof(Elf32_Shdr)
    strtab.sh_size = strpos

    # Write the sections
    file_sections = (Elf32_Shdr * len(sections)).from_buffer(m[end:])
    file_sections[:] = [section for name, section in sections]
    ehdr.e_shnum = len(sections)
    ehdr.e_shstrndx = len(sections)-1
    ehdr.e_shoff = end
    ehdr.e_shentsize = sizeof(Elf32_Shdr)

    offs = strtab.sh_offset
    size = strtab.sh_size
    m[offs:offs+size] = ''.join(strs).encode()

def parse_args(argv):
    import argparse
    parser = argparse.ArgumentParser(description="Recreate the section table for an ELF file")
    parser.add_argument('infile', help="Input file", type=argparse.FileType('rb'))
    parser.add_argument('outfile', help="Output file", type=argparse.FileType('wb+'))

    args = parser.parse_args(argv)
    return args

def main(argv):
    args = parse_args(argv)

    args.outfile.write(args.infile.read())
    origlen = args.infile.tell()
    args.outfile.write(b'\0' * 8192)
    args.infile.close()

    m = mmap.mmap(args.outfile.fileno(), 0)
    reconstruct_sections(m, origlen)

    m.close()
    args.outfile.close()

if __name__ == '__main__':
    import sys
    exit(main(sys.argv[1:]))
