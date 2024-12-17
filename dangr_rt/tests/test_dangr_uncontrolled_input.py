from typing import Callable
from dataclasses import dataclass
import pytest
import angr
from tests.conftest import BinaryBasedTestCase

from dangr_rt.dangr_analysis import DangrAnalysis
from dangr_rt.jasm_findings import JasmMatch, VariableMatch, AddressMatch
from dangr_rt.variables import Variable, Register
from dangr_rt.expression import IsMax

DANGR_DIR = 'dangr_analysis'


@dataclass(kw_only=True)
class UnctrlInTestCase(BinaryBasedTestCase):
    jasm_matches: list
    expected_ptr: Callable[angr.Project, Variable]
    max_depth: int | None = None
    expect_detection: bool = True
    files_directory: str = DANGR_DIR

UNCNTRL_IN_TESTS = [
    UnctrlInTestCase(
        asm_filename='uncontrolled_input.s',
        jasm_matches=[JasmMatch(
            match={0x40_0059:''},
            address_captures=[AddressMatch(name='deref-address', value=0x40_0086)],
            variables=[VariableMatch(name='ptr', value='rax', addr=0x40_0086)]
        )],
        expected_ptr=lambda p: Register(p, 'rax', 0x40_0086),
    ),
    UnctrlInTestCase(
        asm_filename='uncontrolled_input.s',
        jasm_matches=[JasmMatch(
            match={0x40_00cc: ''},
            address_captures=[AddressMatch(name='deref-address', value= 0x40_00dc)],
            variables=[VariableMatch(name='ptr', value='rax', addr=0x40_00dc)]
        )],
        expected_ptr=lambda p: Register(p, 'rax', 0x40_00dc),
    ),
    UnctrlInTestCase(
        asm_filename='uncontrolled_input.s',
        jasm_matches=[JasmMatch(
            match={0x40_008f:''},
            address_captures=[AddressMatch(name='deref-address', value=0x40_00c3)],
            variables=[VariableMatch(name='ptr', value='rax', addr=0x40_00c3)]
        )],
        expected_ptr=lambda p: Register(p, 'rax', 0x40_00c3),
        expect_detection=False
    ),
    UnctrlInTestCase(
        asm_filename='uncontrolled_input.s',
        jasm_matches=[JasmMatch(
            match={0x40_0117:''},
            address_captures=[AddressMatch(name='deref-address', value=0x40_0133)],
            variables=[VariableMatch(name='ptr', value='rax', addr=0x40_0133)]
        )],
        expected_ptr=lambda p: Register(p, 'rax', 0x40_0133),
        expect_detection=False
    ),
]

@pytest.mark.parametrize("test_case", UNCNTRL_IN_TESTS, indirect=True)
def test_software_breakpoint_detection(test_case):
    """
    This a case of use of this proyect it consists on detecting a vulnerability based
    on uncontrolled user input.

    It is reported when a ptr is passed as parameter and then derefereced to write data
    in it but the address of the ptr was never checked.
    """

    dangr = DangrAnalysis(test_case.binary, {'max_depth': test_case.max_depth})

    for struc_find in test_case.jasm_matches:
        dangr.set_finding(struc_find)
        deref_address = struc_find.addrmatch_from_name("deref-address").value

        ptr = dangr.create_var_from_capture(struc_find.varmatch_from_name('ptr'))
        assert ptr == test_case.expected_ptr(dangr.project)

        # idx = vf.create_from_capture(struc_find.captured_regs['idx'])
        # size = vf.create_from_capture(struc_find.captured_regs['size'])

        dangr.add_variables([ptr])

        args = dangr.get_fn_args()
        if all(not dangr.depends(arg, ptr) for arg in args):
            break

        dangr.add_constraint(IsMax(ptr))
        found_states = dangr.simulate(deref_address)

        assert dangr.satisfiable(found_states)
