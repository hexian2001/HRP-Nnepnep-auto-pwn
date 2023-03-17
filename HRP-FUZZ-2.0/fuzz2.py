import sys
import claripy
import angr
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from pwn import *
from typing import List, Union


def find_input_strings(binary_path: str, start_addr: int, end_addr: int, target_addr: int, max_input_size: int) -> Union[None, List[bytes]]:
    elf = ELF(binary_path)
    code = elf.read(start_addr, end_addr  - start_addr)
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = list(disassembler.disasm(code, start_addr))

    plt_reverse = {v: k for k, v in elf.plt.items()}

    project = angr.Project(binary_path, auto_load_libs=False)

    def constrain_inputs(state, start_addr, end_addr, target_addr, conditional_addresses):
        for addr in conditional_addresses:
            var = claripy.BVS("var_{}".format(addr), 32)
            state.memory.store(addr, var)
            state.add_constraints(state.solver.If(state.regs.rip == target_addr, var == 0xFFFFFDC9, True))

    def find_num_inputs(project, disassembler, elf, plt_reverse, instructions):
        input_functions = {'__isoc99_scanf', 'fscanf', 'sscanf', 'read', 'fgets', 'gets'}
        num_inputs = 0
        input_addresses = set()
        conditional_addresses = set()

        for i, instruction in enumerate(instructions):
            if instruction.mnemonic == 'call':
                function_addr = int(instruction.op_str, 16)

                if function_addr in plt_reverse:
                    func_name = plt_reverse[function_addr]

                    if func_name in input_functions:
                        num_inputs += 1

                        prev_instruction = instructions[i - 1]
                        if prev_instruction.mnemonic == 'lea':
                            match = re.search(r'\[rbp(.*?)\]', prev_instruction.op_str)
                            if match:
                                mem_addr = int(match.group(1), 16)
                                input_addresses.add(mem_addr)

        for instruction in instructions:
            if instruction.mnemonic == 'cmp':
                match = re.search(r'\[rbp(.*?)\],', instruction.op_str)
                if match:
                    mem_addr = int(match.group(1), 16)

                    if mem_addr in input_addresses:
                        conditional_addresses.add(mem_addr)

        return num_inputs, conditional_addresses

    def find_inputs_to_reach_target(project, start_addr, end_addr, target_addr, max_input_size, num_inputs, conditional_addresses):
        input_functions = {'__isoc99_scanf', 'fscanf', 'sscanf', 'read', 'fgets', 'gets'}

        for input_size in range(10, max_input_size + 1):
            input_data = [claripy.BVS("input_data_{}".format(i), 8 * input_size) for i in range(num_inputs)]
            input_stream = claripy.Concat(*input_data)

            initial_state = project.factory.blank_state(addr=start_addr, stdin=input_stream)
            constrain_inputs(initial_state, start_addr, end_addr, target_addr, conditional_addresses)

            simulation = project.factory.simulation_manager(initial_state)
            simulation.explore(find=target_addr, avoid=end_addr)

            if simulation.found:
                found_state = simulation.found[0]
                solutions = [found_state.solver.eval(input_data[i], cast_to=bytes) for i in range(num_inputs)]

                input_strings = [re.sub(br'[^a-zA-Z0-9+-]', b'', sol) for sol in solutions]
                return input_strings

        return None

    num_inputs, conditional_addresses = find_num_inputs(project, disassembler, elf, plt_reverse, instructions)
    result = find_inputs_to_reach_target(project, start_addr, end_addr, target_addr, max_input_size, num_inputs, conditional_addresses)

    if result is not None:
        print("Input to reach target address:", result)
        return result
    else:
        print("No input found to reach target address")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python3 script.py <binary_path> <start_address> <end_address> <target_address> <max_input_size>")
        sys.exit(1)

    binary_path = sys.argv[1]
    start_addr = int(sys.argv[2], 16)
    end_addr = int(sys.argv[3], 16)
    target_addr = int(sys.argv[4], 16)
    max_input_size = int(sys.argv[5])

    result = find_input_strings(binary_path, start_addr, end_addr, target_addr, max_input_size)

