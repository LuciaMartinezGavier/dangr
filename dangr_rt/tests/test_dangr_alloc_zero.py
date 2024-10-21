from typing import Callable
from dataclasses import dataclass
import pytest
import angr
from tests.conftest import BinaryBasedTestCase,fullpath

from dangr_rt.dangr_analysis import DangrAnalysis
from dangr_rt.expression import Eq
from dangr_rt.dangr_types import Argument
from dangr_rt.variables import Variable, Register
from dangr_rt.jasm_findings import StructuralFinding

DANGR_DIR = 'dangr_analysis'

@dataclass(kw_only=True)
class AllocZeroTestCase(BinaryBasedTestCase):
    struct_findings: list
    expected_size: Callable[angr.Project, Variable]
    vulnerable: bool
    files_directory: str = DANGR_DIR

HW_BRKP_TESTS = [
    AllocZeroTestCase(
        binary=fullpath(DANGR_DIR, 'small_bmp_support_lib'),
        struct_findings=[
            StructuralFinding([0x40_12c7], {"alloc_call": 0x40_12c7}, {})
        ],
        expected_size=lambda p: Register(p, 'edi', 0x40_12c7),
        vulnerable=True
    ),
    AllocZeroTestCase(
        binary=fullpath(DANGR_DIR, 'small_bmp_support_lib'),
        struct_findings=[
            StructuralFinding([0x40_13a6], {"alloc_call": 0x40_13a6}, {})
        ],
        expected_size=lambda p: Register(p, 'edi', 0x40_13a6),
        vulnerable=False
    )
]

@pytest.mark.parametrize("test_case", HW_BRKP_TESTS, indirect=True)
def test_software_breakpoint_detection(test_case):
    """
    This a case of use of this proyect it consists on detecting a AllocPool called with
    size 0.
    """
    dangr = DangrAnalysis(test_case.binary)
    vf = dangr.get_variable_factory()

    for struc_find in test_case.struct_findings:
        dangr.set_finding(struc_find)
        alloc_call = struc_find.address_captures["alloc_call"]

        size = vf.create_from_argument(Argument(1, alloc_call, 4))
        assert size == test_case.expected_size(dangr.project)

        dangr.add_variables([size])
        dangr.add_constraint(Eq(size, 0))

        found_states = dangr.simulate(alloc_call)
        assert found_states

        assert dangr.satisfiable(found_states)
