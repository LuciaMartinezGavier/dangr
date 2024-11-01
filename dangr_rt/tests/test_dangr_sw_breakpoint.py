import pytest
from dataclasses import dataclass
from typing import Callable
from itertools import chain
import angr
from tests.conftest import BinaryBasedTestCase,fullpath

from dangr_rt.dangr_analysis import DangrAnalysis
from dangr_rt.jasm_findings import CaptureInfo, StructuralFinding
from dangr_rt.variables import Deref, Variable, Register, Literal
from dangr_rt.expression import Eq
from dangr_rt.simulator import ConcreteState

DANGR_DIR = 'dangr_analysis'


@dataclass(kw_only=True)
class SwBrkpTestCase(BinaryBasedTestCase):
    struct_findings: list
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
        struct_findings=[StructuralFinding(
            [0x40_002b, 0x40_0038],
            {'cmp-address': 0x40_0038},
            {
                'ptr': CaptureInfo('rax', 0x40_002b),
                'y': CaptureInfo(0xf223, 0x40_0038),
                'z': CaptureInfo('eax', 0x40_0038),
            }
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
        struct_findings=[StructuralFinding(
            [0x40_0000, 0x40_0002],
            {'cmp-address': 0x40_0002},
            {
                'ptr': CaptureInfo('rdi', 0x40_0000),
                'y': CaptureInfo(0xfa1e0ff3, 0x40_0002),
                'z': CaptureInfo('eax', 0x40_0002),
            }
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
        struct_findings=[StructuralFinding(
            [0x40_0014, 0x40_0021],
            {'cmp-address': 0x40_0021},
            {
                'ptr': CaptureInfo('rax', 0x40_0014),
                'y': CaptureInfo('edx', 0x40_0021),
                'z': CaptureInfo('eax', 0x40_0021),
            }
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
        struct_findings=[StructuralFinding(
            [0x40_d48e, 0x40_d490],
            {'cmp-address': 0x40_d490},
            {
                'ptr': CaptureInfo('rdi', 0x40_d48e),
                'y': CaptureInfo('edx', 0x40_d490),
                'z': CaptureInfo('eax', 0x40_d490),
            }
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
    vf = dangr.get_variable_factory()

    for struc_find in test_case.struct_findings:
        dangr.set_finding(struc_find)
        cmp_address = struc_find.address_captures["cmp-address"]

        ptr = vf.create_from_capture(struc_find.captured_regs['ptr'])
        assert ptr == test_case.expected_ptr(dangr.project)

        y = vf.create_from_capture(struc_find.captured_regs['y'])
        assert y == test_case.expected_y(dangr.project)

        z = vf.create_from_capture(struc_find.captured_regs['z'])
        assert z == test_case.expected_z(dangr.project)

        dx = Deref(ptr, reverse=True)
        assert dx == test_case.expected_dx(dangr.project)

        dangr.add_variables([y,z,dx])

        assert (dangr.depends(dx, y) or dangr.depends(dx, z))

        list_concrete_values = dangr.concretize_fn_args()
        assert test_case.expected_args(dangr.project, list_concrete_values)

        dangr.add_constraint(Eq(y, z))
        dangr.add_constraint(Eq(dx, 0xfa1e0ff3))

        found_states = dangr.simulate(cmp_address, list_concrete_values)
        assert found_states

        assert dangr.satisfiable(found_states)
