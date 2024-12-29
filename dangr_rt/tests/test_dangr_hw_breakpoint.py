from typing import override, Any
from dataclasses import dataclass
import pytest
from tests.conftest import BinaryBasedTestCase,fullpath

from dangr_rt.dangr_analysis import DangrAnalysis
from dangr_rt.jasm_findings import JasmMatch
from dangr_rt.dangr_types import Argument
from dangr_rt.expression import And, Eq

DANGR_DIR = 'dangr_analysis'


@dataclass(kw_only=True)
class HwBrkpTestCase(BinaryBasedTestCase):
    jasm_pattern: Any
    max_depth: int | None = None
    files_directory: str = DANGR_DIR


class HardwareBreakpoint(DangrAnalysis):
    @override
    def _analyze_asm_match(self, jasm_match: JasmMatch) -> bool:
        ptrace_call = jasm_match.addrmatch_from_name("ptrace_call").value
        a1 = self._create_var_from_argument(Argument(1, ptrace_call, 4))
        a3 = self._create_var_from_argument(Argument(3, ptrace_call, 4))

        self._add_constraint(And(Eq(a1, 3), Eq(a3, 848)))
        list_concrete_values = self._concretize_fn_args()

        for concrete_values in list_concrete_values:
            found_states = self._simulate(ptrace_call, concrete_values)
            if self._satisfiable(found_states):
                return True

        return False


HW_BRKP_TESTS = [
    HwBrkpTestCase(
        binary=fullpath(DANGR_DIR, 'hw_breakpoint'),
        jasm_pattern='mock hardware_breakpoint',
        max_depth=4
    )
]

@pytest.mark.parametrize("test_case", HW_BRKP_TESTS, indirect=True)
def test_hardware_breakpoint_detection(test_case):
    """
    This a case of use of this proyect it consists on detecting a debug evation.

    It is reported when the binary is trying to detect a hardware breakpoint
    which is detemined if when the debug registers are being read through the syscall ptrace
    """
    analysis = HardwareBreakpoint(test_case.binary, {'max_depth': test_case.max_depth})
    assert analysis.analyze(test_case.jasm_pattern)
