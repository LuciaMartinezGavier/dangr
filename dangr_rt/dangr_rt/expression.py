from typing import override
from abc import ABC, abstractmethod
from itertools import product

from dangr_rt.dangr_types import AngrExpr, Address, Bool, BYTE_SIZE
from dangr_rt.variables import Variable

class ExpressionNode(ABC):

    @abstractmethod
    def create_expressions(self) -> list[AngrExpr]:
        """
        From the ExpressionNode obtain an angr expression
        """

    @abstractmethod
    def expression_address(self) -> Address:
        """
        Get the address on which the Expression should be applied
        """

    @abstractmethod
    def size(self) -> int:
        """
        Return the size (in bits) of the expression
        """

class IsMaxNode(ExpressionNode):
    def __init__(self, expr: ExpressionNode, offset: int = 0):
        self.expr = expr
        self.offset = offset

    @override
    def create_expressions(self) -> list[AngrExpr]:
        return self.expr == 2**(self.expr.size() * BYTE_SIZE) - self.offset

    @override
    def size(self) -> int:
        return self.expr.size()

    @override
    def expression_address(self) -> Address:
        return self.expr.expression_address()

    def __repr__(self) -> str:
        return f'IsMaxNode({self.expr!r})'

class VarNode(ExpressionNode):
    def __init__(self, variable: Variable) -> None:
        self.variable = variable

    @override
    def create_expressions(self) -> list[AngrExpr]:
        return list(self.variable.angr_repr().values())

    @override
    def expression_address(self) -> Address:
        return self.variable.ref_addr

    @override
    def size(self) -> int:
        return self.variable.size()

    def __repr__(self) -> str:
        return f'VarNode({self.variable!r})'

class BinaryOpNode(ExpressionNode):
    def __init__(self, lh: ExpressionNode, rh: ExpressionNode):
        if lh.size() != rh.size():
            raise ValueError("Mismatch of expression sizes")

        self.lh = lh
        self.rh = rh

    @override
    def expression_address(self) -> Address:
        return max(self.lh.expression_address(), self.rh.expression_address())

    @override
    def size(self) -> int:
        return self.lh.size()

class EqualNode(BinaryOpNode):
    @override
    def create_expressions(self) -> list[AngrExpr]:
        return [
            lh == rh for lh, rh in # type: ignore [misc]
            product(self.lh.create_expressions(), self.rh.create_expressions())
        ]

    def __repr__(self) -> str:
        return f'{self.lh!r} == {self.rh!r}'

class AndNode(BinaryOpNode):
    @override
    def create_expressions(self) -> list[AngrExpr]:
        lh_expr = self.lh.create_expressions()
        rh_expr = self.rh.create_expressions()
        if not all(isinstance(sub_expr, Bool) for sub_expr in lh_expr + rh_expr):
            raise TypeError(f"Unsupported operand type(s): {self.lh!r} + {self.rh!r}")
        return list(set(lh & rh for lh, rh in product(lh_expr, rh_expr))) # type: ignore [operator]

class SumNode(BinaryOpNode):
    @override
    def create_expressions(self) -> list[AngrExpr]:
        lh_expr = self.lh.create_expressions()
        rh_expr = self.rh.create_expressions()

        if any(isinstance(sub_expr, Bool) for sub_expr in lh_expr + rh_expr):
            raise TypeError(f"Unsupported operand type(s): {self.lh!r} + {self.rh!r}")

        return list(set(lh + rh for lh, rh in product(lh_expr, rh_expr))) # type: ignore [operator]

    def __repr__(self) -> str:
        return f'{self.lh!r} + {self.rh!r}'

class MultNode(BinaryOpNode):
    @override
    def create_expressions(self) -> list[AngrExpr]:
        lh_expr = self.lh.create_expressions()
        rh_expr = self.rh.create_expressions()

        if any(isinstance(sub_expr, Bool) for sub_expr in lh_expr + rh_expr):
            raise TypeError(f"Unsupported operand type(s): {self.lh!r} * {self.rh!r}")

        return list(set(lh * rh for lh, rh in product(lh_expr, rh_expr))) # type: ignore [operator]

    def __repr__(self) -> str:
        return f'{self.lh!r} + {self.rh!r}'
