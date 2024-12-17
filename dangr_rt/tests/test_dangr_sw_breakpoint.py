from dataclasses import dataclass
from typing import Callable
import pytest

import angr
from tests.conftest import BinaryBasedTestCase,fullpath

from dangr_rt.dangr_analysis import DangrAnalysis
from dangr_rt.jasm_findings import JasmMatch, VariableMatch, AddressMatch
from dangr_rt.variables import Deref, Variable, Register, Literal
from dangr_rt.expression import Eq
from dangr_rt.simulator import ConcreteState

DANGR_DIR = 'dangr_analysis'


@dataclass(kw_only=True)
class SwBrkpTestCase(BinaryBasedTestCase):
    jasm_matches: list
    expected_args: Callable[[angr.Project, list[ConcreteState]], bool]
    expected_ptr: Callable[angr.Project, Variable]
    expected_y: Callable[angr.Project, Variable]
    expected_z: Callable[angr.Project, Variable]
    expected_dx: Callable[angr.Project, Variable]
    reverse: bool
    max_depth: int | None = None
    files_directory: str = DANGR_DIR


SW_BRKP_TESTS = [
    SwBrkpTestCase(
        asm_filename='sw_breakpoint_xz_analysis.s',
        max_depth=2,
        jasm_matches=[JasmMatch(
            match={
                0x40_002b: "some_instruction",
                0x40_0038: "some_instruction"
            },
            address_captures=[
                AddressMatch(name='cmp-address', value=0x40_0038)
            ],
            variables=[
                VariableMatch(name="ptr",value='rax', addr=0x40_002b),
                VariableMatch('y', value=0xf223, addr=0x40_0038),
                VariableMatch(name='z', value='eax', addr=0x40_0038)
            ]
        )],
        expected_args=lambda p, args: args and all(
            a.get(Register(p, 'edx', 0x40_000c), 0) == 57904 for a in args
        ),

        expected_dx=lambda p: Deref(Register(p, 'rax', 0x40_002b)),
        expected_ptr=lambda p: Register(p, 'rax', 0x40_002b),
        expected_y=lambda p: Literal(p, 0xf223, 0x40_0038),
        expected_z=lambda p: Register(p, 'eax', 0x40_0038),
        reverse=True
    ),
    SwBrkpTestCase(
        asm_filename='sw_breakpoint_trivial.s',
        max_depth=2,
        jasm_matches=[JasmMatch(
            match={
                0x40_0000: 'some_instruction',
                0x40_0002: 'some_instruction'
            },
            address_captures=[AddressMatch(name='cmp-address', value=0x40_0002)],
            variables=[
                VariableMatch(name='ptr', value='rdi', addr=0x40_0000),
                VariableMatch(name='y', value=0xfa1e0ff3, addr=0x40_0002),
                VariableMatch(name='z', value='eax', addr=0x40_0002)
            ],
        )],
        expected_args=lambda p, args: len(args) == 0,

        expected_dx=lambda p: Deref(Register(p, 'rdi', 0x40_0000)),
        expected_ptr=lambda p: Register(p, 'rdi', 0x40_0000),
        expected_y=lambda p: Literal(p, 0xfa1e0ff3, 0x40_0002),
        expected_z=lambda p: Register(p, 'eax', 0x40_0002),
        reverse=True
    ),
    SwBrkpTestCase(
        asm_filename='sw_breakpoint_branches.s',
        max_depth=5,
        jasm_matches=[JasmMatch(
            match={0x40_0014:'ignore', 0x40_0021: 'ignore'},
            address_captures=[AddressMatch(name='cmp-address', value=0x40_0021)],
            variables=[
                VariableMatch(name='ptr', value='rax', addr=0x40_0014),
                VariableMatch(name='y',   value='edx', addr=0x40_0021),
                VariableMatch(name='z',   value='eax', addr=0x40_0021)
            ]
        )],
        expected_args=lambda p, args: args == [
            {
                Register(p, 'edi', 0x40_0004): 0x544300,
                Register(p, 'esi', 0x40_0007): 0x12545f78,
                Register(p, 'edx', 0x40_000a): 0xe7c9b07b,
            },
            {
                Register(p, 'edi', 0x40_0004): 0x544300,
                Register(p, 'esi', 0x40_0007): 0x12545f78,
                Register(p, 'edx', 0x40_000a): 0x10101010,
            },
        ],

        expected_dx=lambda p: Deref(Register(p, 'rax', 0x40_0014)),
        expected_ptr=lambda p: Register(p, 'rax', 0x40_0014),
        expected_y=lambda p: Register(p, 'edx', 0x40_0021),
        expected_z=lambda p: Register(p, 'eax', 0x40_0021),
        reverse=True
    ),
    SwBrkpTestCase(
        binary=fullpath(DANGR_DIR, 'liblzma.so.5.6.1'),
        max_depth=1,
        jasm_matches=[JasmMatch(
            match={0x40_d48e:'', 0x40_d490:''},
            address_captures=[AddressMatch(name='cmp-address', value=0x40_d490)],
            variables=[
                VariableMatch(name='ptr', value='rdi', addr=0x40_d48e),
                VariableMatch(name='y', value='edx', addr=0x40_d490),
                VariableMatch(name='z', value='eax', addr=0x40_d490)
            ]
        )],
        expected_args=lambda p, args: [
            {Register(p, 'edx', 0x40_d45f): 57904},
            {Register(p, 'edx', 0x40_d45f): 57904},
            {Register(p, 'edx', 0x40_d45f): 57904},
            {Register(p, 'edx', 0x40_d45f): 57904},
            {}
        ],

        expected_dx=lambda p: Deref(Register(p, 'rdi', 0x40_d48e)),
        expected_ptr=lambda p: Register(p, 'rdi', 0x40_d48e),
        expected_y=lambda p: Register(p, 'edx', 0x40_d490),
        expected_z=lambda p: Register(p, 'eax', 0x40_d490),
        reverse=False
    ),
]

@pytest.mark.parametrize("test_case", SW_BRKP_TESTS, indirect=True)
def test_software_breakpoint_detection(test_case):
    """
    This is the first case of use of this proyect it consists on detecting a debug evation.

    It is reported when the binary is trying to detect a software breakpoint
    which is detemined if when a pointer is involved in a comparison and
    the comparison is True if the contents of the memory are the ENDBR64 opcode.
    """
    dangr = DangrAnalysis(test_case.binary, {'max_depth': test_case.max_depth})

    for struc_find in test_case.jasm_matches:
        dangr.set_finding(struc_find)
        cmp_address = struc_find.addrmatch_from_name("cmp-address").value

        ptr = dangr.create_var_from_capture(struc_find.varmatch_from_name('ptr'))
        assert ptr == test_case.expected_ptr(dangr.project)

        y = dangr.create_var_from_capture(struc_find.varmatch_from_name('y'))
        assert y == test_case.expected_y(dangr.project)

        z = dangr.create_var_from_capture(struc_find.varmatch_from_name('z'))
        assert z == test_case.expected_z(dangr.project)

        dx = Deref(ptr, reverse=True)
        assert dx == test_case.expected_dx(dangr.project)

        dangr.add_variables([y,z,dx, ptr])

        assert (dangr.depends(dx, y) or dangr.depends(dx, z))

        list_concrete_values = dangr.concretize_fn_args()
        assert test_case.expected_args(dangr.project, list_concrete_values)

        dangr.add_constraint(Eq(y, z))
        dangr.add_constraint(Eq(dx, 0xfa1e0ff3))

        found_states = dangr.simulate(cmp_address, list_concrete_values)
        assert found_states

        assert dangr.satisfiable(found_states)
