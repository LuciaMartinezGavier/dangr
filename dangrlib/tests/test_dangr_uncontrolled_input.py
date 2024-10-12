import pytest
from dataclasses import dataclass
from typing import Callable
from itertools import chain
import angr
from tests.compilation_utils import BinaryBasedTestCase, compile_assembly,fullpath

from dangrlib.dangr_analysis import DangrAnalysis
from dangrlib.jasm_findings import CaptureInfo, StructuralFinding
from dangrlib.variables import Deref, Variable, Register, Literal
from dangrlib.expression import EqualNode, VarNode
from dangrlib.dangr_types import Argument
from dangrlib.simulator import ConcreteState

DANGR_DIR = 'dangr_analysis'


@dataclass
class UnctrlInTestCase(BinaryBasedTestCase):
    struct_findings: list
    expected_ptr: Callable[angr.Project, Variable]
    max_depth: int | None = None
    expect_detection: bool = True



UNCNTRL_IN_TESTS = [
    UnctrlInTestCase(
        asm_filename='uncontrolled_input.s',
        struct_findings=[StructuralFinding(
            [0x40_0059],
            {'deref-address': 0x40_0086},
            {'ptr': CaptureInfo('rax', 0x40_0086)}
        )],
        expected_ptr=lambda p: Register(p, 'rax', 0x40_0086),
    ),
    UnctrlInTestCase(
        asm_filename='uncontrolled_input.s',
        struct_findings=[StructuralFinding(
            [0x40_00cc],
            {'deref-address': 0x40_00dc},
            {'ptr': CaptureInfo('rax', 0x40_00dc)}
        )],
        expected_ptr=lambda p: Register(p, 'rax', 0x40_00dc),
    ),
    UnctrlInTestCase(
        asm_filename='uncontrolled_input.s',
        struct_findings=[StructuralFinding(
            [0x40_008f],
            {'deref-address': 0x40_00c3},
            {'ptr': CaptureInfo('rax', 0x40_00c3)}
        )],
        expected_ptr=lambda p: Register(p, 'rax', 0x40_00c3),
        expect_detection=False
    ),
    UnctrlInTestCase(
        asm_filename='uncontrolled_input.s',
        struct_findings=[StructuralFinding(
            [0x40_0117],
            {'deref-address': 0x40_0133},
            {'ptr': CaptureInfo('rax', 0x40_0133)}
        )],
        expected_ptr=lambda p: Register(p, 'rax', 0x40_0133),
        expect_detection=False
    ),
]

@pytest.mark.parametrize("test_case", UNCNTRL_IN_TESTS)
@compile_assembly(DANGR_DIR)
def test_software_breakpoint_detection(test_case):
    """
    This a case of use of this proyect it consists on detecting a vulnerability based
    on uncontrolled user input.

    It is reported when a ptr is passed as parameter and then derefereced to write data
    in it but the address of the ptr was never checked.
    """

    dangr = DangrAnalysis(test_case.binary, max_depth=test_case.max_depth)
    vf = dangr.get_variable_factory()

    for struc_find in test_case.struct_findings:
        dangr.set_finding(struc_find)
        vf = dangr.get_variable_factory()
        deref_address = struc_find.address_captures["deref-address"]

        ptr = vf.create_from_capture(struc_find.captured_regs['ptr'])
        assert ptr == test_case.expected_ptr(dangr.project)

        # idx = vf.create_from_capture(struc_find.captured_regs['idx'])
        # size = vf.create_from_capture(struc_find.captured_regs['size'])

        dangr.add_variables([ptr])

        args = dangr.get_fn_args()
        if all(not dangr.depends(arg, ptr) for arg in args):
            break

        found_states = dangr.simulate(deref_address)

        found = not dangr.upper_bounded(VarNode(ptr), found_states, Deref(ptr).size())
        #, MultNode(idx,size))):

        assert found == test_case.expect_detection
