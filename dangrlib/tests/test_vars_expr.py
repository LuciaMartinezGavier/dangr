import angr
import pytest
from typing import Final, Callable
from dataclasses import dataclass

from tests.compilation_utils import compile_assembly, BinaryBasedTestCase
from copy import deepcopy
from dangrlib.variables import Variable, Register, Literal, Memory, Deref
from dangrlib.variable_factory import VariableFactory
from dangrlib.dangr_types import Address, Argument
from dangrlib.jasm_findings import CaptureInfo
from dangrlib.expression import ExpressionNode, VarNode, EqualNode, SumNode, MultNode
import re

EXPR_DIR = 'exprs'
VARS_ASM = 'vars.s'
ADDR = 40_0000
MEM = 0x1a1a_e0e0

@dataclass(kw_only=True)
class VarFactTestCase(BinaryBasedTestCase):
    create_method_name: str
    args: list[CaptureInfo | Argument | str | Address]
    expected: Variable
    asm_filename: str = VARS_ASM

@dataclass(kw_only=True)
class VarTestCase(BinaryBasedTestCase):
    var: Callable[angr.Project, Variable]
    expected_size: int
    expected_repr: str
    expected_neq: Callable[angr.Project, Variable]
    asm_filename: str = VARS_ASM

@dataclass(kw_only=True)
class ExprTestCase(BinaryBasedTestCase):
    asm_filename: str = VARS_ASM
    expr: Callable[angr.Project, ExpressionNode]
    expected_expr: str
    expected_addr: list[Address]
    expected_size: int
    set_ref_state: Callable[list[angr.SimState], None]


VARFACTORY_TESTS = [
    VarFactTestCase(
        create_method_name='create_from_capture',
        args=[CaptureInfo('rdi', ADDR)],
        expected=lambda p: Register(p, 'rdi', ADDR)
    ),
    VarFactTestCase(
        create_method_name='create_from_capture',
        args=[CaptureInfo(0x123, ADDR)],
        expected=lambda p: Literal(p, 0x123, ADDR)
    ),
    VarFactTestCase(
        create_method_name='create_from_capture',
        args=[CaptureInfo(0x123, ADDR)],
        expected=lambda p: Literal(p, 0x123, ADDR)
    ),
    VarFactTestCase(
        create_method_name='create_from_argument',
        args=[Argument(1, ADDR, 8)],
        expected=lambda p: Register(p,'rdi', ADDR)
    ),
    VarFactTestCase(
        create_method_name='create_from_argument',
        args=[Argument(1, ADDR, 4)],
        expected=lambda p: Register(p,'edi', ADDR)
    ),
    VarFactTestCase(
        create_method_name='create_from_angr_name',
        args=['reg_rdx_507_64', ADDR],
        expected=lambda p: Register(p, 'rdx', ADDR)
    ),
    VarFactTestCase(
        create_method_name='create_from_angr_name',
        args=['mem_ffffe00000000000_17_32', ADDR],
        expected=lambda p: Memory(p, 0xffffe00000000000, 4, ADDR)
    ),
]

VAR_TESTS = [
    VarTestCase(
        var=lambda p: Register(p, 'edi', ADDR),
        expected_size=4,
        expected_repr=f'<Register edi in {hex(ADDR)}>',
        expected_neq=lambda p: Deref(Register(p, 'edi', ADDR))
    ),
    VarTestCase(
        var=lambda p: Memory(p, MEM, 32, ADDR),
        expected_size=32,
        expected_repr=f'<Memory ({hex(MEM)}, 32) reference in {hex(ADDR)}>',
        expected_neq=lambda p: Deref(Register(p, 'rax', ADDR))
    ),
    VarTestCase(
        var=lambda p: Literal(p, 0x410_a71, 0x40_0004),
        expected_size=4,
        expected_repr=f'<Literal {0x410a71} in 0x400004>',
        expected_neq=lambda p: Memory(p, 0x410_a71, 4, 0x40_0004)
    ),
    VarTestCase(
        var=lambda p: Deref(Register(p, 'rax', 0x40_001e)),
        expected_size=4,
        expected_repr='<Deref $0 + <Register rax in 0x40001e>>',
        expected_neq=lambda p: Memory(p, 0x40_001e, 4, 0x40_001e)
    )
]

EXPR_TESTS = [
    ExprTestCase(
        expr=lambda p: VarNode(Register(p, 'rdi', 0x40_0016)),
        expected_size=8,
        expected_expr="<BV64 reg_rdi_[0-9]+_64>",
        expected_addr=0x40_0016,
        set_ref_state=lambda expr, sts: expr.variable.set_ref_states(sts)
    ),
    ExprTestCase(
        expr=lambda p: EqualNode(
            VarNode(Register(p, 'rdi', 0x40_0016)),
            VarNode(Deref(Register(p, 'rbp', 0x40_0016), -8))
        ),
        expected_size=8,
        expected_expr="<Bool reg_rdi_[0-9]+_64 == mem_[0-9a-f]+_[0-9]+_64>",

        expected_addr=0x40_0016,
        set_ref_state=lambda expr, sts: [
            expr.lh.variable.set_ref_states(sts),
            expr.rh.variable.set_ref_states(sts)
        ]
    ),
    ExprTestCase(
        expr=lambda p: SumNode(
            VarNode(Register(p, 'rdi', 0x40_0016)),
            VarNode(Register(p, 'rax', 0x40_001a))
        ),
        expected_size=8,
        expected_expr="<BV64 reg_rdi_[0-9]+_64 \+ reg_rax_[0-9]+_64>",

        expected_addr=0x40_001a,
        set_ref_state=lambda expr, sts: [
            expr.lh.variable.set_ref_states(sts),
            expr.rh.variable.set_ref_states(sts)
        ]
    ),
    ExprTestCase(
        expr=lambda p: MultNode(
            VarNode(Memory(p, MEM, 4, 0x40_0012)),
            VarNode(Register(p, 'eax', 0x40_001e))
        ),
        expected_size=4,
        expected_expr=f'<BV32 mem_1a1ae0e0_[0-9]+_32 \* reg_eax_[0-9]+_32>',
        expected_addr=0x40_001e,
        set_ref_state=lambda expr, sts: [
            expr.lh.variable.set_ref_states(sts),
            expr.rh.variable.set_ref_states(sts)
        ]
    )
]

@pytest.mark.parametrize("test_case", VARFACTORY_TESTS)
@compile_assembly(EXPR_DIR)
def test_variable_factory(test_case):
    p = angr.Project(test_case.binary, auto_load_libs=False)
    vf = VariableFactory(p)
    var_factory_create = getattr(vf, test_case.create_method_name)
    variable = var_factory_create(*test_case.args)
    assert variable == test_case.expected(p)

def test_variable_factory_err():
    p = angr.Project('/bin/ls', auto_load_libs=False)
    vf = VariableFactory(p)
    with pytest.raises(ValueError):
        vf.create_from_capture(CaptureInfo(None, 0x40_0000))

    with pytest.raises(ValueError):
        vf.create_from_argument(Argument(0, ADDR, 8))

    with pytest.raises(ValueError):
        vf.create_from_angr_name('lit_12345_32', ADDR)


@pytest.mark.parametrize("test_case", VAR_TESTS)
@compile_assembly(EXPR_DIR)
def test_variable(test_case):
    p = angr.Project(test_case.binary, auto_load_libs=False)
    vf = VariableFactory(p)
    var = test_case.var(p)
    default_state = p.factory.blank_state()
    N: Final = 5
    VALUE: Final = 123

    with pytest.raises(ValueError):
        var.dependencies(vf)

    assert f'{var!r}' == test_case.expected_repr

    other = deepcopy(var)
    other.project = var.project

    if isinstance(var, Deref):
        var.base.project = other.base.project

    other.set_ref_states([default_state])
    assert var == other
    assert var != test_case.expected_neq(p)

    assert var.size() == test_case.expected_size

    var.set_ref_states([default_state]*N)
    assert set(var.angr_repr().keys()) == var.reference_states

    if isinstance(var, Literal):
        with pytest.raises(ValueError):
            var.set_value(VALUE)
    else:
        for s in var.reference_states:
            var.set_value(VALUE)
            assert VALUE == var.evaluate()[s]

@pytest.mark.parametrize("test_case", EXPR_TESTS)
@compile_assembly(EXPR_DIR)
def test_expression(test_case):
    p = angr.Project(test_case.binary, auto_load_libs=False)
    expr = test_case.expr(p)

    test_case.set_ref_state(expr, [p.factory.blank_state()])

    assert all(re.search(test_case.expected_expr, str(e)) for e in expr.create_expressions())
    assert expr.expression_address() == test_case.expected_addr
    assert expr.size() == test_case.expected_size

def test_expression_err():
    p = angr.Project('/bin/ls', auto_load_libs=False)
    with pytest.raises(ValueError):
        MultNode(VarNode(Register(p, 'rdi', 0x40_0016)),
                 VarNode(Register(p, 'eax', 0x40_001e)))
