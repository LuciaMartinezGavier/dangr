from typing import Callable
from dataclasses import dataclass
import pytest
import angr
from tests.conftest import BinaryBasedTestCase,fullpath

from dangr_rt.dangr_analysis import DangrAnalysis
from dangr_rt.jasm_findings import JasmMatch, AddressMatch
from dangr_rt.variables import Variable, Register, Literal
from dangr_rt.dangr_types import Argument
from dangr_rt.expression import And, Eq
from dangr_rt.simulator import ConcreteState

DANGR_DIR = 'dangr_analysis'


@dataclass(kw_only=True)
class HwBrkpTestCase(BinaryBasedTestCase):
    jasm_matches: list
    expected_args: Callable[[angr.Project, list[ConcreteState]], bool]
    expected_a1: Callable[angr.Project, Variable]
    expected_a3: Callable[angr.Project, Variable]
    max_depth: int | None = None
    files_directory: str = DANGR_DIR


HW_BRKP_TESTS = [
    HwBrkpTestCase(
        binary=fullpath(DANGR_DIR, 'hw_breakpoint'),
        jasm_matches=[
            JasmMatch(
                match={0x40_11f3:''},
                address_captures=[AddressMatch(name="ptrace_call", value=0x40_11f3)],
                variables=[]
            )
        ],
        expected_args=lambda p, args: args == [{
            Register(p, 'esi', 0x40_11d4): 212,
            Register(p, 'edx', 0x40_11d7): 3,
        }],
        expected_a1=lambda p: Register(p, 'edi', 0x40_11f3),
        expected_a3=lambda p: Register(p, 'edx', 0x40_11f3),
        max_depth=4
    )
]

@pytest.mark.parametrize("test_case", HW_BRKP_TESTS, indirect=True)
def test_software_breakpoint_detection(test_case):
    """
    This a case of use of this proyect it consists on detecting a debug evation.

    It is reported when the binary is trying to detect a hardware breakpoint
    which is detemined if when the debug registers are being read through the syscall ptrace
    """
    dangr = DangrAnalysis(test_case.binary, {'max_depth': test_case.max_depth})
    vf = dangr.get_variable_factory()

    for struc_find in test_case.jasm_matches:
        dangr.set_finding(struc_find)
        ptrace_call = struc_find.addrmatch_from_name("ptrace_call").value

        a1 = vf.create_from_argument(Argument(1, ptrace_call, 4))

        assert a1 == test_case.expected_a1(dangr.project)

        a3 = vf.create_from_argument(Argument(3, ptrace_call, 4))
        assert a3 == test_case.expected_a3(dangr.project)

        dangr.add_variables([a1, a3])

        list_concrete_values = dangr.concretize_fn_args()
        assert test_case.expected_args(dangr.project, list_concrete_values)

        dangr.add_constraint(And(Eq(a1, 3), Eq(a3, 848)))

        found_states = dangr.simulate(ptrace_call, list_concrete_values)
        assert found_states
        assert dangr.satisfiable(found_states)
