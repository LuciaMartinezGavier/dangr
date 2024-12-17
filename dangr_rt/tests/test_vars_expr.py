import re
import pytest
from copy import deepcopy
from typing import Final, Callable
from dataclasses import dataclass
import angr
import claripy
from tests.conftest import BinaryBasedTestCase
from dangr_rt.variables import Variable, Register, Literal, Memory, Deref
from dangr_rt.variable_factory import VariableFactory
from dangr_rt.dangr_types import Address, Argument
from dangr_rt.jasm_findings import VariableMatch
from dangr_rt.expression import Expression, Eq, Add, Mul

VARS_ASM = 'vars.s'
ADDR = 40_0000
MEM = 0x1a1a_e0e0

@dataclass(kw_only=True)
class VarFactTestCase(BinaryBasedTestCase):
    create_method_name: str
    args: list[VariableMatch | Argument | str | Address]
    expected: Variable
    asm_filename: str = VARS_ASM
    files_directory: str = 'exprs'

@dataclass(kw_only=True)
class VarTestCase(BinaryBasedTestCase):
    var: Callable[angr.Project, Variable]
    expected_size: int
    expected_repr: str
    expected_neq: Callable[angr.Project, Variable]
    asm_filename: str = VARS_ASM
    files_directory: str = 'exprs'

@dataclass(kw_only=True)
class ExprTestCase(BinaryBasedTestCase):
    asm_filename: str = VARS_ASM
    expr: Callable[angr.Project, Expression]
    expected_expr: str
    expected_addr: list[Address]
    set_ref_state: Callable[list[angr.SimState], None]
    files_directory: str = 'exprs'

VARFACTORY_TESTS = [
    VarFactTestCase(
        create_method_name='create_from_capture',
        args=[VariableMatch(name='a', value='rdi', addr=ADDR)],
        expected=lambda p: Register(p, 'rdi', ADDR)
    ),
    VarFactTestCase(
        create_method_name='create_from_capture',
        args=[VariableMatch(name='test', value=0x123, addr=ADDR)],
        expected=lambda p: Literal(p, 0x123, ADDR)
    ),
    VarFactTestCase(
        create_method_name='create_from_capture',
        args=[VariableMatch(name='test', value=0x123, addr=ADDR)],
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
    )
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
        expr=lambda p: Register(p, 'rdi', 0x40_0016),
        expected_expr="<BV64 reg_rdi_[0-9]+_64>",
        expected_addr=0x40_0016,
        set_ref_state=lambda expr, st: expr.set_ref_state(st)
    ),
    ExprTestCase(
        expr=lambda p: Eq(
            Register(p, 'rdi', 0x40_0016),
            Deref(Register(p, 'rbp', 0x40_0016), -8)
        ),
        expected_expr="<Bool reg_rdi_[0-9]+_64 == Reverse\(mem_[0-9a-f]+_[0-9]+_64\)>",

        expected_addr=0x40_0016,
        set_ref_state=lambda expr, st: [
            expr.lhs.set_ref_state(st),
            expr.rhs.set_ref_state(st)
        ]
    ),
    ExprTestCase(
        expr=lambda p: Add(
            Register(p, 'rdi', 0x40_0016),
            Register(p, 'rax', 0x40_001a)
        ),
        expected_expr="<BV64 reg_rdi_[0-9]+_64 \+ reg_rax_[0-9]+_64>",

        expected_addr=0x40_001a,
        set_ref_state=lambda expr, st: [
            expr.lhs.set_ref_state(st),
            expr.rhs.set_ref_state(st)
        ]
    ),
    ExprTestCase(
        expr=lambda p: Mul(
            Memory(p, MEM, 4, 0x40_0012),
            Register(p, 'eax', 0x40_001e)
        ),
        expected_expr=f'<BV32 Reverse\(mem_1a1ae0e0_[0-9]+_32\) \* reg_eax_[0-9]+_32>',
        expected_addr=0x40_001e,
        set_ref_state=lambda expr, st: [
            expr.lhs.set_ref_state(st),
            expr.rhs.set_ref_state(st)
        ]
    )
]

@pytest.mark.parametrize("test_case", VARFACTORY_TESTS, indirect=True)
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
        vf.create_from_capture(VariableMatch(name='test', value=None, addr=0x40_0000))

    with pytest.raises(ValueError):
        vf.create_from_argument(Argument(0, ADDR, 8))



@pytest.mark.parametrize("test_case", VAR_TESTS, indirect=True)
def test_variable(test_case):
    p = angr.Project(test_case.binary, auto_load_libs=False)
    vf = VariableFactory(p)
    var = test_case.var(p)
    default_state = p.factory.blank_state()
    N: Final = 5
    VALUE: Final = 123

    assert f'{var!r}' == test_case.expected_repr

    other = deepcopy(var)
    other.project = var.project

    if isinstance(var, Deref):
        var.base.project = other.base.project

    other.set_ref_state(default_state)
    assert var == other
    assert var != test_case.expected_neq(p)

    assert var.size() == test_case.expected_size

    var.set_ref_state(default_state)

    if isinstance(var, Literal):
        with pytest.raises(ValueError):
            var.set_value(VALUE)
    else:
        var.set_value(VALUE)
        assert VALUE == var.evaluate()

@pytest.mark.parametrize("test_case", EXPR_TESTS, indirect=True)
def test_expression(test_case):
    p = angr.Project(test_case.binary, auto_load_libs=False)
    expr = test_case.expr(p)

    test_case.set_ref_state(expr, p.factory.blank_state())

    assert re.search(test_case.expected_expr, str(expr.get_expr()))
    assert expr.ref_addr == test_case.expected_addr

def test_expression_err():
    p = angr.Project('/bin/ls', auto_load_libs=False)
    reg1 = Register(p, 'rdi', 0x40_0016)
    reg1.set_ref_state(p.factory.blank_state())
    reg2 = Register(p, 'eax', 0x40_001e)
    reg2.set_ref_state(p.factory.blank_state())

    with pytest.raises(claripy.errors.ClaripyOperationError):
        Mul(reg1, reg2).get_expr()
