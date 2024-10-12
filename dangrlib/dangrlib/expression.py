from typing import override
from abc import ABC, abstractmethod
from itertools import product
from dangrlib.dangr_types import AngrExpr, Address
from dangrlib.variables import Variable

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

    def __repr__(self) -> None:
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
            lh == rh for lh, rh in
            product(self.lh.create_expressions(), self.rh.create_expressions())
        ]

    def __repr__(self) -> None:
        return f'{self.lh!r} == {self.rh!r}'

class SumNode(BinaryOpNode):
    @override
    def create_expressions(self) -> list[AngrExpr]:
        return [
            lh + rh for lh, rh in 
            product(self.lh.create_expressions(), self.rh.create_expressions())
        ]

    def __repr__(self) -> None:
        return f'{self.lh!r} + {self.rh!r}'

class MultNode(BinaryOpNode):
    @override
    def create_expressions(self) -> list[AngrExpr]:
        return [
            lh * rh for lh, rh in
            product(self.lh.create_expressions(), self.rh.create_expressions())
        ]

    def __repr__(self) -> None:
        return f'{self.lh!r} + {self.rh!r}'
