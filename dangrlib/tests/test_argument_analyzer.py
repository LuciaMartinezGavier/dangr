import pytest
from typing import Final, Callable
from dataclasses import dataclass
import angr
from tests.compilation_utils import compile_assembly, BinaryBasedTestCase
from dangrlib.arguments_analyzer import ArgumentsAnalyzer
from dangrlib.dangr_types import Address
from dangrlib.variables import Register, Variable
from dangrlib.simulator import ConcreteState

@dataclass
class ArgumentsTestCase(BinaryBasedTestCase):
    """
    All the info needed to create a case test
    max_depth: explore max_depth steps backwards to get arg values 
    """
    fn_addr: Address
    expected_args: Callable[angr.Project, list[Variable]]
    expected_values: Callable[angr.Project, list[ConcreteState]]
    max_depth: int | None = None

ARG_ANALYZER_DIR = 'arguments_analyzer'

ARG_ANALYZER_TESTS: Final = [
    ArgumentsTestCase(
        asm_filename='not_optimized.s',
        fn_addr=0x40_0000,
        expected_args=lambda proj: [],
        expected_values=lambda proj: [{}],
        max_depth=1,
    ),
    ArgumentsTestCase(
        asm_filename='not_optimized.s',
        fn_addr=0x40_000b,
        expected_args=lambda proj: [
            Register(proj, 'edi', 0x40_000f),
            Register(proj, 'esi', 0x40_0012)
        ],
        expected_values=lambda proj: [
            {
                Register(proj, 'edi', 0x40_000f): 1,
                Register(proj, 'esi', 0x40_0012): 3,
            },
            {
                Register(proj, 'esi', 0x40_0012): 3
            }
        ],
        max_depth=1,
    ),
    ArgumentsTestCase(
        asm_filename='not_optimized.s',
        fn_addr=0x40_000b,
        expected_args=lambda proj: [
            Register(proj, 'edi', 0x40_000f),
            Register(proj, 'esi', 0x40_0012)
        ],
        expected_values=lambda proj: [
            {
                Register(proj, 'edi', 0x40_000f): 1,
                Register(proj, 'esi', 0x40_0012): 3,
            },
            {
                Register(proj, 'edi', 0x40_000f): 42,
                Register(proj, 'esi', 0x40_0012): 3,
            },
        ],
        max_depth=2,
    ),
    ArgumentsTestCase(
        asm_filename='not_optimized.s',
        fn_addr=0x40_0056,
        expected_args=lambda proj: [
            Register(proj, 'rdi', 0x40_005a),
            Register(proj, 'rsi', 0x40_005e),
            Register(proj, 'edx', 0x40_0062),
        ],
        expected_values=lambda proj: [{
            Register(proj, 'rsi', 0x40_005e): 1,
            Register(proj, 'edx', 0x40_0062): 0,
        }],
        max_depth=2,
    ),
    ArgumentsTestCase(
        asm_filename='not_optimized.s',
        fn_addr=0x40_007b,
        expected_args=lambda proj: [
            Register(proj, 'edi', 0x40_007f),
            Register(proj, 'esi', 0x40_0082),
        ],
        expected_values=lambda proj: [{
            Register(proj, 'edi', 0x40_007f): 6,
            Register(proj, 'esi', 0x40_0082): 7,
        }],
        max_depth=1,
    ),
    ArgumentsTestCase(
        asm_filename='optimized.s',
        fn_addr=0x40_0000,
        expected_args=lambda proj: [
            Register(proj, 'edi', 0x40_0000),
        ],
        expected_values=lambda proj: [
            { Register(proj, 'edi', 0x40_0000): 148504 }, {}, {},
            { Register(proj, 'edi', 0x40_0000): 3 }
        ],
        max_depth=5,
    ),

]

@pytest.mark.parametrize("test_case", ARG_ANALYZER_TESTS)
@compile_assembly(ARG_ANALYZER_DIR)
def test_argument_analyzer(test_case):
    """Test if the arguments are correctly found"""
    project = angr.Project(test_case.binary, auto_load_libs=False)
    cfg = project.analyses.CFGFast()
    arg_analyzer = ArgumentsAnalyzer(project, cfg, test_case.max_depth)
    arguments = arg_analyzer.get_fn_args(test_case.fn_addr)
    assert arguments ==  test_case.expected_args(project)

    concrete_states = arg_analyzer.solve_arguments(test_case.fn_addr, arguments)

    assert len(test_case.expected_values(project)) == len(concrete_states)
    assert all([
        actual == expected for actual, expected
        in zip(concrete_states, test_case.expected_values(project))
    ])
