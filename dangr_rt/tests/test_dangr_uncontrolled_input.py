from typing import override, Any
from dataclasses import dataclass
import pytest
from tests.conftest import BinaryBasedTestCase
from dangr_rt.dangr_analysis import DangrAnalysis
from dangr_rt.jasm_findings import JasmMatch
from dangr_rt.expression import IsMax

DANGR_DIR = 'dangr_analysis'


@dataclass(kw_only=True)
class UnctrlInTestCase(BinaryBasedTestCase):
    jasm_pattern: Any
    max_depth: int | None = None
    expect_detection: bool = True
    files_directory: str = DANGR_DIR
    call_depth: int | None = None

UNCNTRL_IN_TESTS = [
    UnctrlInTestCase(
        asm_filename='uncontrolled_input.s',
        jasm_pattern='mock uncontrolled_input_0078',
        call_depth=3
    ),
    UnctrlInTestCase(
        asm_filename='uncontrolled_input.s',
        jasm_pattern='mock uncontrolled_input_00ce',
        call_depth=3
    ),
    UnctrlInTestCase(
        asm_filename='uncontrolled_input.s',
        jasm_pattern='mock uncontrolled_input_00b5',
        call_depth=3,
        expect_detection=False,
    ),
    UnctrlInTestCase(
        asm_filename='uncontrolled_input.s',
        jasm_pattern='mock uncontrolled_input_0125',
        expect_detection=False,
    ),
]


class UncontrolledInput(DangrAnalysis):
    def __init__(self, binary_path, config, jasm_pattern) -> None:
        super().__init__(binary_path, config)
        self.jasm_pattern = jasm_pattern

    @property
    @override
    def _jasm_pattern(self) -> dict:
        return self.jasm_pattern

    @property
    @override
    def meta(self) -> dict:
        return {}

    @override
    def _analyze_asm_match(self, jasm_match: JasmMatch) -> bool:
        deref_address = jasm_match.addrmatch_from_name("deref-address").value
        ptr = self._create_var_from_capture(jasm_match.varmatch_from_name('ptr'))

        args = self._get_fn_args()

        if all(not self._depends(arg, ptr) for arg in args):
            return False

        self._add_constraint(IsMax(ptr))
        found_states = self._simulate(deref_address)
        return self._satisfiable(found_states)

@pytest.mark.parametrize("test_case", UNCNTRL_IN_TESTS, indirect=True)
def test_uncontrolled_input(test_case):
    """
    This a case of use of this proyect it consists on detecting a vulnerability based
    on uncontrolled user input.

    It is reported when a ptr is passed as parameter and then derefereced to write data
    in it but the address of the ptr was never checked.
    """
    config = {
        'cfg_call_depth': test_case.call_depth,
        'max_depth': test_case.max_depth
    }
    analysis = UncontrolledInput(test_case.binary, config, test_case.jasm_pattern)
    assert analysis.analyze() == test_case.expect_detection
