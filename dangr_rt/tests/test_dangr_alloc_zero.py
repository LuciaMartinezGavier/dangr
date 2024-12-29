from typing import Any, override
from dataclasses import dataclass
import pytest
from tests.conftest import BinaryBasedTestCase,fullpath

from dangr_rt.dangr_analysis import DangrAnalysis
from dangr_rt.expression import Eq
from dangr_rt.dangr_types import Argument
from dangr_rt.jasm_findings import JasmMatch

DANGR_DIR = 'dangr_analysis'

@dataclass(kw_only=True)
class AllocZeroTestCase(BinaryBasedTestCase):
    jasm_pattern: Any
    vulnerable: bool
    files_directory: str = DANGR_DIR

ALLOC_ZERO_TESTS = [
    AllocZeroTestCase(
        binary=fullpath(DANGR_DIR, 'small_bmp_support_lib'),
        jasm_pattern='mock small_bmp_support_lib_12c5',
        vulnerable=True
    ),
    AllocZeroTestCase(
        binary=fullpath(DANGR_DIR, 'small_bmp_support_lib'),
        jasm_pattern='mock small_bmp_support_lib_1339',
        vulnerable=False
    ),
]

class AllocZero(DangrAnalysis):
    @override
    def _analyze_asm_match(self, jasm_match: JasmMatch) -> bool:
        alloc_call = jasm_match.addrmatch_from_name("alloc_call").value
        size = self._create_var_from_argument(Argument(1, alloc_call, 4))

        self._add_constraint(Eq(size, 0))

        found_states = self._simulate(alloc_call)
        return self._satisfiable(found_states)

@pytest.mark.parametrize("test_case", ALLOC_ZERO_TESTS, indirect=True)
def test_alloc_zero(test_case):
    """
    This a case of use of this proyect it consists on detecting a AllocPool called with
    size 0.
    """
    analysis = AllocZero(test_case.binary, {})
    assert analysis.analyze(test_case.jasm_pattern) == test_case.vulnerable
