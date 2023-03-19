import sys
from capstone import *
from pwn import *

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 elf_functions.py <path-to-elf-file>")
        sys.exit(1)

    elf_file_path = sys.argv[1]
    elf = ELF(elf_file_path)

    User_Function = {}

    for section in elf.iter_sections():
        if section.is_executable() and section.name == ".text":
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            data = section.data()
            base_addr = section.header.sh_addr

            for i in md.disasm(data, base_addr):
                if i.mnemonic == 'call':
                    func_start = hex(i.operands[0].imm)
                    func_end = hex(i.address + i.size)
                    if func_start not in User_Function:
                        User_Function[func_start] = func_end

    print("User_Function: ", User_Function)

if __name__ == '__main__':
    main()
