from dataclasses import dataclass
from typing import override, Any
import pytest
from tests.conftest import BinaryBasedTestCase,fullpath
from dangr_rt.dangr_analysis import DangrAnalysis
from dangr_rt.jasm_findings import JasmMatch
from dangr_rt.expression import Eq, Not

DANGR_DIR = 'dangr_analysis'


@dataclass(kw_only=True)
class SwBrkpTestCase(BinaryBasedTestCase):
    jasm_pattern: Any
    reverse: bool
    max_depth: int | None = None
    files_directory: str = DANGR_DIR

SW_BRKP_TESTS = [
    SwBrkpTestCase(
        asm_filename='sw_breakpoint_xz_analysis.s',
        max_depth=2,
        jasm_pattern='mock software_breakpoint_0038',
        reverse=True
    ),
    SwBrkpTestCase(
        asm_filename='sw_breakpoint_trivial.s',
        max_depth=2,
        jasm_pattern='mock software_breakpoint_0002',
        reverse=True
    ),
    SwBrkpTestCase(
        asm_filename='sw_breakpoint_branches.s',
        max_depth=5,
        jasm_pattern='mock software_breakpoint_0021',
        reverse=True
    ),
    SwBrkpTestCase(
        binary=fullpath(DANGR_DIR, 'liblzma.so.5.6.1'),
        max_depth=1,
        jasm_pattern='mock software_breakpoint_d490',
        reverse=True
    ),
]

class SoftwareBreakpoint(DangrAnalysis):
    @override
    def _analyze_asm_match(self, jasm_match: JasmMatch) -> bool:
        cmp_address = jasm_match.addrmatch_from_name("cmp-address").value
        ptr = self._create_var_from_capture(jasm_match.varmatch_from_name('ptr'))
        y = self._create_var_from_capture(jasm_match.varmatch_from_name('y'))
        z = self._create_var_from_capture(jasm_match.varmatch_from_name('z'))
        dx = self._create_deref(ptr)

        self._add_constraint(Eq(y, z))
        self._add_constraint(Not(Eq(dx, 0xfa1e0ff3)))

        list_concrete_values = self._concretize_fn_args()

        for concrete_values in list_concrete_values:
            found_states = self._simulate(cmp_address, concrete_values)
            if not self._satisfiable(found_states):
                return True

        return False

@pytest.mark.parametrize("test_case", SW_BRKP_TESTS, indirect=True)
def test_software_breakpoint_detection(test_case):
    """
    This is the first case of use of this proyect it consists on detecting a debug evation.

    It is reported when the binary is trying to detect a software breakpoint
    which is detemined if when a pointer is involved in a comparison and
    the comparison is True if the contents of the memory are the ENDBR64 opcode.
    """
    config = {
        'max_depth': test_case.max_depth,
        'reverse': test_case.reverse
    }

    analysis = SoftwareBreakpoint(test_case.binary, config)
    assert analysis.analyze(test_case.jasm_pattern)
