from dataclasses import dataclass
from typing import Final, Callable
import pytest
import angr
from tests.compilation_utils import BinaryBasedTestCase, compile_assembly
from dangrlib.dependency_analyzer import DependencyAnalyzer
from dangrlib.variables import Variable, Register, Memory, Deref, Literal
from dangrlib.variable_factory import VariableFactory
from dangrlib.dangr_types import Address

@dataclass
class DependencyTestCase(BinaryBasedTestCase):
    """
    All the info needed to create a case test

    func_addr: Function address in the binary
    source: given a project cretates the source variable
    target: given a project cretates the target variable
    expected: Expected result (True if dependency exists)
    call_depth: call_depth (optional)
    """
    func_addr: Address
    source: Callable[angr.Project, Variable]
    target: Callable[angr.Project, Variable]
    expected: bool
    call_depth: int | None = None

DEP_ANALYZER_DIR = 'dependency_analyzer'
DEP_ANALYZER_TESTS: Final = [
    DependencyTestCase(
        asm_filename="mini.s",
        func_addr=0x400000,
        source=lambda proj: Register(proj, "rbx", 0x400000),
        target=lambda proj: Register(proj, "ebx", 0x400005),
        expected=True
    ),
    DependencyTestCase(
        asm_filename="deref.s",
        func_addr=0x400000,
        source=lambda proj: Deref(Register(proj, "rax", 0x40000f)),
        target=lambda proj: Register(proj, "eax", 0x400030),
        expected=True
    ),
    DependencyTestCase(
        asm_filename="deref.s",
        func_addr=0x400035,
        source=lambda proj: Deref(Register(proj, "rax", 0x400049)),
        target=lambda proj: Deref(Register(proj, "rax", 0x40005c)),
        expected=True
    ),
    DependencyTestCase(
        asm_filename="deref.s",
        func_addr=0x400060,
        source=lambda proj: Deref(Register(proj, "rdi", 0x400060)),
        target=lambda proj: Memory(proj, 0x40000000, 0x4, 0x400062),
        expected=True
    ),
    DependencyTestCase(
        asm_filename="memory.s",
        func_addr=0x400000,
        source=lambda proj: Memory(proj, 0x40000000, 0x4, 0x400008),
        target=lambda proj: Deref(Register(proj, "rax", 0x40001c)),
        expected=True
    ),
    DependencyTestCase(
        asm_filename="memory.s",
        func_addr=0x400021,
        source=lambda proj: Memory(proj, 0x12345678, 0x4, 0x400021),
        target=lambda proj: Memory(proj, 0x10000000, 0x4, 0x400028),
        expected=True
    ),
    DependencyTestCase(
        asm_filename="memory.s",
        func_addr=0x400030,
        source=lambda proj: Memory(proj, 0x12345678, 0x4, 0x400039),
        target=lambda proj: Register(proj, 'edx', 0x400040),
        call_depth=1,
        expected=True
    ),
    DependencyTestCase(
        asm_filename="register.s",
        func_addr=0x400000,
        source=lambda proj: Register(proj, 'edi', 0x400004),
        target=lambda proj: Deref(Register(proj, 'rax', 0x400015)),
        call_depth=1,
        expected=True
    ),
    DependencyTestCase(
        asm_filename="register.s",
        func_addr=0x40001a,
        source=lambda proj: Register(proj, 'edi', 0x40001e),
        target=lambda proj: Memory(proj, 0x101010, 0x4, 0x400024),
        call_depth=1,
        expected=True
    ),
    DependencyTestCase(
        asm_filename="register.s",
        func_addr=0x40002e,
        source=lambda proj: Register(proj, 'edi', 0x400032),
        target=lambda proj: Register(proj, 'eax', 0x400042),
        call_depth=1,
        expected=True
    ),
    DependencyTestCase(
        asm_filename="literal.s",
        func_addr=0x400000,
        source=lambda proj: Literal(proj, 0x10, 0x400008),
        target=lambda proj: Deref(Register(proj, 'rax', 0x400023)),
        call_depth=1,
        expected=True
    ),
    DependencyTestCase(
        asm_filename="literal.s",
        func_addr=0x400027,
        source=lambda proj: Literal(proj, 0xe0e0e, 0x40003b),
        target=lambda proj: Memory(proj, 0x1a1a1a, 0x4, 0x40003b),
        call_depth=1,
        expected=True
    ),
    DependencyTestCase(
        asm_filename="literal.s",
        func_addr=0x400044,
        source=lambda proj: Literal(proj, 0xea, 0x400048),
        target=lambda proj: Register(proj, 'eax', 0x40004f),
        call_depth=1,
        expected=True
    ),
    DependencyTestCase(
        asm_filename="literal.s",
        func_addr=0x40006d,
        source=lambda proj: Literal(proj, 0x64, 0x40006d),
        target=lambda proj: Register(proj, 'edi', 0x400072),
        call_depth=1,
        expected=True
    ),
    DependencyTestCase(
        asm_filename="literal.s",
        func_addr=0x400044,
        source=lambda proj: Register(proj, 'edi', 0x400058),
        target=lambda proj: Literal(proj, 0x18, 0x400066),
        call_depth=1,
        expected=False
    ),
]


@pytest.mark.parametrize("test_case", DEP_ANALYZER_TESTS)
@compile_assembly(DEP_ANALYZER_DIR)
def test_check_dependency(test_case):
    """Test checking a dependency between variables."""
    project = angr.Project(test_case.binary, auto_load_libs=False)
    variable_factory = VariableFactory(project)
    analyzer = DependencyAnalyzer(project, variable_factory, call_depth=test_case.call_depth)
    analyzer.create_dependency_graph(test_case.func_addr)

    assert analyzer.ddg is not None
    assert len(analyzer.ddg.graph.nodes) > 0

    result = analyzer.check_dependency(
        test_case.source(project),
        test_case.target(project)
    )

    assert result == test_case.expected
