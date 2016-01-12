Stack layouts - from the top of the stack downwards.

# OS X

## 32-bit

    TOP:
    TOPPAD: 100 bytes of 0s (thread area?)
            1-4 bytes of padding so that EXE is aligned 4
    ENVSTR: Environment variable strings (packed)
    ARGSTR: Argument strings (packed)
    EXE:    Executable filename (might be relative)
            void*[5]:   5 pointers: [EXE, TOP-100, TOP-85, TOP-54, NULL]
    ENVP:   void*[]:    Pointers to each environment variable, ends with NULL
    ARGV:   void*[]:    Pointers to each argument, ends with NULL
    ARGC:   int:        Number of arguments

## 64-bit

    TOP:
    TOPPAD: 104 bytes of 0s (thread area?)
            1-8 bytes of padding so that EXE is aligned 8
    ENVSTR: Environment variable strings (packed)
    ARGSTR: Argument strings (packed)
    EXE:    Executable filename (might be relative)
            void*[5]:   5 pointers: [EXE, TOP-104, TOP-85, TOP-54, NULL]
    ENVP:   void*[]:    Pointers to each environment variable, ends with NULL
    ARGV:   void*[]:    Pointers to each argument, ends with NULL
    ARGC:   int:        Number of arguments

# Linux

## 32-bit

    TOP:
    4 bytes padding
    EXE:    Executable filename (might be relative)
    ENVSTR: Environment variable strings (packed)
    ARGSTR: Argument strings (packed)
            Padding to align 16
    ARCH:   "i686\0"
    RAND:   16 bytes of random data
            Padding so that ARGC is aligned 16
    AUXV:   auxv vectors. Relevant, always-present auxv:
                AT_NULL: Ends the array
                AT_PLATFORM: Pointer to ARCH
                AT_EXECFN: Pointer to EXE
                AT_RANDOM: Pointer to RAND
                AT_SECURE: [0|1]
                AT_EGID, AT_GID, AT_EUID, AT_UID
                AT_ENTRY
                AT_FLAGS
                AT_BASE, AT_PHNUM, AT_PHENT, AT_PHDR
                AT_CLKTCK
                AT_PAGESZ
                AT_HWCAP
    ENVP:   void*[]:    Pointers to each environment variable, ends with NULL
    ARGV:   void*[]:    Pointers to each argument, ends with NULL
    ARGC:   int:        Number of arguments
    _start frame
