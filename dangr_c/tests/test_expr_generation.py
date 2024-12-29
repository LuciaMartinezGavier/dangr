import pytest
from dangr_c.expr_parser import WhereExprParser, SuchThatExprParser
from dangr_c.visitor import ExprType, WhereExprVisitor, SuchThatExprVisitor

WHERE_EXPR = [
    (
        'a1 = arg(1, ptrace_call, 1)',
        { 'where': { 'asgn' : {
            'lv': 'a1',
            'rv': { 'arg' : {
                'idx': '1',
                'call': 'ptrace_call',
                'size': '1',
            }}
        }}},
        'a1 = self._create_var_from_argument(Argument(1, ptrace_call, 1))',
        ExprType.ASSIGN
    ),
    (
        'a3 = arg(3, ptrace_call, 4)',
        { 'where': { 'asgn': {
            'lv': 'a3',
            'rv': { 'arg': {
                'idx': '3',
                'call': 'ptrace_call',
                'size': '4'
            }}
        }}},
        'a3 = self._create_var_from_argument(Argument(3, ptrace_call, 4))',
        ExprType.ASSIGN
    ),
    (
        'size = arg(4, alloc_call, 1)',
        { 'where': { 'asgn': {
            'lv': 'size',
            'rv': { 'arg': {
                'idx': '4',
                'call': 'alloc_call',
                'size': '1'
            }}
        }}},
        'size = self._create_var_from_argument(Argument(4, alloc_call, 1))',
        ExprType.ASSIGN
    ),
    (
        'dx = *ptr',
        { 'where': { 'asgn': {
            'lv': 'dx',
            'rv': { 'deref': { 'var': 'ptr'}}
        }}},
        'dx = self._create_deref(ptr)',
        ExprType.ASSIGN
    ),
    (
        '(dx -> y) or (dx -> z)',
        { 'where': { 'or': {
            'lft': {'dep': {'src': 'dx', 'trg': 'y'}},
            'rgt': {'dep': {'src': 'dx', 'trg': 'z'}}
        }}},
        '(self._depends(dx, y) or self._depends(dx, z))',
        ExprType.DEP_EXPR
    ),
    (
        '(dx -> t)',
        {'where': {'dep': {'src': 'dx', 'trg': 't'}}},
        'self._depends(dx, t)',
        ExprType.DEP_EXPR
    ),
    (
        'not ((a -> b) and (b -> c))',
        { 'where': { 'not': { 'exp': { 'and': {
            'lft': {'dep': {'src': 'a', 'trg': 'b'}},
            'rgt': {'dep': {'src': 'b', 'trg': 'c'}}
        }}}}},
        '(not (self._depends(a, b) and self._depends(b, c)))',
        ExprType.DEP_EXPR
    ),
    (
        '(_anyarg -> foo)',
        { 'where': { 'dep': {'src': '_anyarg', 'trg': 'foo'}}},
        'any(self._depends(_arg, foo) for _arg in self._get_fn_args())',
        ExprType.DEP_EXPR
    ),
    (
        '(foo -> _anyarg) and (a -> b)',
        { 'where': { 'and': {
            'lft': {'dep': {'src': 'foo', 'trg': '_anyarg'}},
            'rgt': {'dep': {'src': 'a', 'trg': 'b'}}
        }}},
        '(any(self._depends(foo, _arg) for _arg in self._get_fn_args()) and self._depends(a, b))',
        ExprType.DEP_EXPR
    ),
]

such_that = [
    (
        'a1 = 3',
        {'such_that': {'eq': {'lft': 'a1', 'rgt': '3'}}},
        'Eq(a1, 3)'
    ),
    (
        'a3 = 848',
        {'such_that': {'eq': {'lft': 'a3', 'rgt': '848'}}},
        'Eq(a3, 848)'
    ),
    (
        'size = 0',
        {'such_that': {'eq': {'lft': 'size', 'rgt': '0'}}},
        'Eq(size, 0)'
    ),
    (
        'y = z',
        {'such_that': {'eq': {'lft': 'y', 'rgt': 'z'}}},
        'Eq(y, z)'
    ),
    (
        'y * lala = z + pepe',
        { 'such_that': { 'eq': {
            'lft': {'mul': {'lft': 'y', 'rgt': 'lala'}},
            'rgt': {'add': {'lft': 'z', 'rgt': 'pepe'}}
        }}},
        'Eq(Mul(y, lala), Add(z, pepe))'
    ),
    (
        'y = lala and a*b = c',
        { 'such_that': { 'and': {
            'lft': {'eq': {'lft': 'y', 'rgt': 'lala'}},
            'rgt': {'eq': {'lft': {'mul': {'lft': 'a', 'rgt': 'b'}}, 'rgt': 'c'}}
        }}},
        'And(Eq(y, lala), Eq(Mul(a, b), c))'
    ),
    (
        'dx = 0xFA1E0FF3',
        {'such_that': {'eq': {'lft': 'dx', 'rgt': '0xFA1E0FF3'}}},
        'Eq(dx, 0xFA1E0FF3)'
    ),
    (
        'not (a1 = a2 or a3 = 534)',
        { 'such_that': { 'not': { 'exp': { 'or': {
            'lft': {'eq': {'lft': 'a1', 'rgt': 'a2'}},
            'rgt': {'eq': {'lft': 'a3', 'rgt': '534'}}
        }}}}},
        'Not(Or(Eq(a1, a2), Eq(a3, 534)))'
    ),
    (
        'upper_unbounded(ptr + idx*size)',
        { 'such_that': { 'upper_unbounded': { 'bounded_exp': { 'add': {
            'lft': 'ptr',
            'rgt': {'mul': {
                'lft': 'idx',
                'rgt': 'size'
            }}
        }}}}},
        'IsMax(Add(ptr, Mul(idx, size)))'

    ),
    (
        'upper_unbounded(ptr) and (a = b)',
        {'such_that': {'and': {
            'lft': {'upper_unbounded': {'bounded_exp': 'ptr'}},
            'rgt': {'eq': {'lft': 'a', 'rgt': 'b'}}
        }}},
        'And(IsMax(ptr), Eq(a, b))'
    ),

]

@pytest.mark.parametrize("expr,expected_ast,expected_gen,expected_type", WHERE_EXPR)
def test_where_expr_generation(expr, expected_ast, expected_gen, expected_type):
    """Test that WHERE_EXPR expressions are parsed correctly."""
    ast = WhereExprParser().parse(expr)
    assert expected_ast == ast
    visitor =  WhereExprVisitor()
    visitor.visit(ast)
    assert visitor.formula == expected_gen
    assert visitor.expr_type == expected_type

@pytest.mark.parametrize("expr,expected_ast,expected_gen", such_that)
def test_such_that_generation(expr, expected_ast, expected_gen):
    """Test that such_that expressions are parsed correctly."""
    ast = SuchThatExprParser().parse(expr)
    assert expected_ast == ast
    visitor =  SuchThatExprVisitor()
    visitor.visit(ast)
    assert visitor.formula == expected_gen
    assert visitor.expr_type == ExprType.CONSTR
