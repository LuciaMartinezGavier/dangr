from abc import ABC
from enum import Enum, auto

class ASTVisitor(ABC):
    """
    Base class for AST visitors. 
    Defines generic visit method and specific methods for each node type.
    """
    def _children_names(self, node):
        return list(node.keys())

    def visit(self, node):
        """
        The main visit method dispatches to specific node visit methods based on node type.
        """
        if isinstance(node, str):
            visit_method = getattr(self, "visit_atom", self.generic_visit)
            visit_method(node)
            return

        children_names = self._children_names(node)
        for child_name in children_names:
            visit_method = getattr(self, f"visit_{child_name}", self.generic_visit)
            visit_method(node[child_name])
        return

    def generic_visit(self, node):
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
    def __init__(self, reverse: bool | None = None):
        self.reverse = reverse
        self.formula: str = ''
        self.expr_type: ExprType | None = None

    def visit_where(self, node):
        self.formula = ''
        self.visit(node)

    def visit_asgn(self, node):
        self.expr_type = ExprType.ASSIGN
        self.visit(node['lv'])
        self.formula += ' = '
        self.visit(node['rv'])

    def visit_arg(self, node):
        self.formula += 'vf.create_from_argument(Argument('
        self.visit(node['idx'])
        self.formula += ', '
        self.visit(node['call'])
        self.formula += ', '
        self.visit(node['size'])
        self.formula += '))'

    def visit_deref(self, node):
        self.formula += 'Deref('
        self.visit(node['var'])
        if self.reverse:
            self.formula += ', reverse=True'
        self.formula += ')'

    def visit_atom(self, node):
        if node == '_anyarg':
            self.formula += '_arg'
        else:
            self.formula += node


    def visit_not(self, node):
        self.formula += '(not '
        self.visit(node)
        self.formula += ')'

    def visit_or(self, node):
        self.formula += '('
        self.visit(node['lft'])
        self.formula += ' or '
        self.visit(node['rgt'])
        self.formula += ')'

    def visit_and(self, node):
        self.formula += '('
        self.visit(node['lft'])
        self.formula += ' and '
        self.visit(node['rgt'])
        self.formula += ')'

    def visit_dep(self, node):
        self.expr_type = ExprType.DEP_EXPR
        current_formula = self.formula

        self.formula = ''
        self.visit(node['src'])
        src = self.formula

        self.formula = ''
        self.visit(node['trg'])
        trg = self.formula

        self.formula = current_formula
        basic_dep = f'dangr.depends({src}, {trg})'

        if src == '_arg' and trg == '_arg':
            raise ValueError(
                'Invalid dependency "(_anyarg -> _anyarg)": '
                '_anyarg should occur in only one side of dependency expression'
            )
        elif src == '_arg' or trg == '_arg':
            self.formula += f'some({basic_dep} for _arg in dangr.get_fn_args())'
        else:
            self.formula += basic_dep


class SuchThatExprVisitor(ASTVisitor):
    def __init__(self):
        self.formula = ''
        self.expr_type: ExprType | None = None

    def _visit_binary_exp(self, node, node_name):
        self.formula += node_name + '('
        self.visit(node['lft'])
        self.formula += ', '
        self.visit(node['rgt'])
        self.formula += ')'

    def visit_such_that(self, node) -> None:
        self.expr_type = ExprType.CONSTR
        self.formula = ''
        self.visit(node)

    def visit_upper_unbounded_ptr(self, node) -> None:
        self.formula += 'IsMaxPtr('
        self.visit(node['bounded_exp'])
        self.formula += ')'

    def visit_add(self, node) -> None:
        self._visit_binary_exp(node, 'Add')

    def visit_mul(self, node) -> None:
        self._visit_binary_exp(node, 'Mul')

    def visit_sub(self, node) -> None:
        self._visit_binary_exp(node, 'Sub')

    def visit_div(self, node) -> None:
        self._visit_binary_exp(node, 'Div')

    def visit_atom(self, node) -> None:
        self.formula += node

    def visit_eq(self, node) -> None:
        self._visit_binary_exp(node, 'Eq')

    def visit_not(self, node):
        self.formula += 'Not('
        self.visit(node['exp'])
        self.formula += ')'

    def visit_or(self, node):
        self._visit_binary_exp(node, 'Or')

    def visit_and(self, node):
        self._visit_binary_exp(node, 'And')
