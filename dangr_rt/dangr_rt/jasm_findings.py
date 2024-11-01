
from typing import Any
from dataclasses import dataclass
from dangr_rt.dangr_types import Address

@dataclass
class CaptureInfo:
    captured: str | int
    address: int
# NOTE: Pattern obj  y Match obj

class StructuralFinding:
    def __init__(
        self,
        instr_address: list[int],
        address_captures: dict[str, Address],
        captured_regs: dict[str, CaptureInfo]
    ):

        if not instr_address:
            raise ValueError("No instruction found in pattern match")

        self.instr_address = instr_address
        self.start: Address = instr_address[0]
        self.end: Address = instr_address[-1]
        self.address_captures = address_captures
        self.captured_regs = captured_regs


def _run_jasm() -> None:
    pass

def _parse_jasm_output() -> None:
    pass


def structural_filter(binary_path: str, jasm_pattern: dict[str, Any]) -> list[StructuralFinding]:
    _run_jasm()
    _, _= binary_path, jasm_pattern
    _parse_jasm_output()
    return hardware_breakpoint_mock()

def hardware_breakpoint_mock() -> list[StructuralFinding]:
    return [StructuralFinding([0x40_11f3], {"ptrace_call": 0x40_11f3}, {})]

def software_breakpoint_mock1() -> list[StructuralFinding]:
    """
    TODO: Where does the register's address come from?
    We could do some changes to the jasm pattern before 
    executing so we can savee the register's use location
    """
    # detect('/home/luciamg/debug_detection2/tests/test_files/software_breakpoint', '')
    return [StructuralFinding(
        [0x401194, 0x4011a1],
        {'cmp-address': 0x4011a1},
        {
            'ptr': CaptureInfo('rax', 0x401194),
            'y': CaptureInfo(0xf223, 0x4011a1),
            'z': CaptureInfo('eax', 0x4011a1),
        }
    )]

def software_breakpoint_mock() -> list[StructuralFinding]:
    # detect('/home/luciamg/debug_detection2/tests/test_files/liblzma.so.5.6.1', '')
    return [StructuralFinding(
        [0x40d48e, 0x40d490],
        {'cmp-address': 0x40d490},
        {
            'ptr': CaptureInfo('rdi', 0x40d48e),
            'y': CaptureInfo('edx', 0x40d490),
            'z': CaptureInfo('eax', 0x40d490),
        }
    )]

def uncontrolled_input_mock() -> list[StructuralFinding]:
    return [StructuralFinding(
        [0x4011bf],
        {'deref-address': 0x4011bf},
        {
            'ptr': CaptureInfo('rax', 0x4011bf),
        }
    )]
