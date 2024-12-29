from abc import ABC
from enum import Enum, auto
from dangr_c.expr_parser import NodeName, Atom, Parent, Node

class ASTVisitor(ABC):
    """
    Base class for AST visitors.
    Defines generic visit method and specific methods for each node type.
    """
    def _children_names(self, node: Parent) -> list[NodeName]:
        return list(node.keys())

    def visit(self, node: Node) -> None:
        """
        The main visit method dispatches to specific node visit methods based on node type.
        """
        if isinstance(node, Atom):
            visit_method = getattr(self, "visit_atom", self.generic_visit)
            visit_method(node)
            return

        children_names = self._children_names(node)
        for child_name in children_names:
            visit_method = getattr(self, f"visit_{child_name}", self.generic_visit)
            visit_method(node[child_name])

    def generic_visit(self, node: Node) -> None:
        """
        Fallback visit method for unhandled node types.
        """
        if isinstance(node, str):
            return

        self.visit(node)

class ExprType(Enum):
    ASSIGN = auto()
    DEP_EXPR = auto()
    CONSTR = auto()


class WhereExprVisitor(ASTVisitor):
    def __init__(self, reverse: bool | None = None) -> None:
        self.reverse = reverse
        self.formula: str = ''
        self.expr_type: ExprType | None = None

    def visit_atom(self, node: Atom) -> None:
        if node == '_anyarg':
            self.formula += '_arg'
        else:
            self.formula += node

    def visit_where(self, node: Parent) -> None:
        self.formula = ''
        self.visit(node)

    def visit_asgn(self, node: Parent) -> None:
        self.expr_type = ExprType.ASSIGN
        lv = self._build_subformula(node['lv'])
        self.formula += f'{lv} = '
        self.visit(node['rv'])

    def visit_arg(self, node: Parent) -> None:
        self.formula += 'self._create_var_from_argument(Argument('
        self.visit(node['idx'])
        self.formula += ', '
        self.visit(node['call'])
        self.formula += ', '
        self.visit(node['size'])
        self.formula += '))'

    def visit_deref(self, node: Parent) -> None:
        self.formula += 'self._create_deref('
        self.visit(node['var'])
        if self.reverse:
            self.formula += ', reverse=True'
        self.formula += ')'

    def visit_not(self, node: Parent) -> None:
        self.formula += '(not '
        self.visit(node)
        self.formula += ')'

    def visit_or(self, node: Parent) -> None:
        self.formula += '('
        self.visit(node['lft'])
        self.formula += ' or '
        self.visit(node['rgt'])
        self.formula += ')'

    def visit_and(self, node: Parent) -> None:
        self.formula += '('
        self.visit(node['lft'])
        self.formula += ' and '
        self.visit(node['rgt'])
        self.formula += ')'

    def visit_dep(self, node: Parent) -> None:
        self.expr_type = ExprType.DEP_EXPR

        src = self._build_subformula(node['src'])
        trg = self._build_subformula(node['trg'])
        self._dep_check_if_valid(src, trg)

        basic_dep = f'self._depends({src}, {trg})'
        if src == '_arg' or trg == '_arg':
            self.formula += f'any({basic_dep} for _arg in self._get_fn_args())'
            return

        self.formula += basic_dep

    def _build_subformula(self, node: Node) -> str:
        old_formula = self.formula
        self.formula = ''
        self.visit(node)
        formula = self.formula
        self.formula = old_formula
        return formula

    def _dep_check_if_valid(self, src: Atom, trg: Atom) -> None:
        if src == '_arg' and trg == '_arg':
            raise ValueError(
                'Invalid dependency "(_anyarg -> _anyarg)": '
                '_anyarg should occur in only one side of dependency expression'
            )

class SuchThatExprVisitor(ASTVisitor):
    def __init__(self) -> None:
        self.formula = ''
        self.expr_type: ExprType | None = None

    def visit_atom(self, node: Atom) -> None:
        self.formula += node

    def _visit_binary_exp(self, node: Parent, node_name: NodeName) -> None:
        self.formula += node_name + '('
        self.visit(node['lft'])
        self.formula += ', '
        self.visit(node['rgt'])
        self.formula += ')'

    def visit_such_that(self, node: Parent) -> None:
        self.expr_type = ExprType.CONSTR
        self.formula = ''
        self.visit(node)

    def visit_upper_unbounded(self, node: Parent) -> None:
        self.formula += 'IsMax('
        self.visit(node['bounded_exp'])
        self.formula += ')'

    def visit_add(self, node: Parent) -> None:
        self._visit_binary_exp(node, 'Add')

    def visit_mul(self, node: Parent) -> None:
        self._visit_binary_exp(node, 'Mul')

    def visit_sub(self, node: Parent) -> None:
        self._visit_binary_exp(node, 'Sub')

    def visit_div(self, node: Parent) -> None:
        self._visit_binary_exp(node, 'Div')

    def visit_eq(self, node: Parent) -> None:
        self._visit_binary_exp(node, 'Eq')

    def visit_not(self, node: Parent) -> None:
        self.formula += 'Not('
        self.visit(node['exp'])
        self.formula += ')'

    def visit_or(self, node: Parent) -> None:
        self._visit_binary_exp(node, 'Or')

    def visit_and(self, node: Parent) -> None:
        self._visit_binary_exp(node, 'And')
