from typing import override
from abc import ABC, abstractmethod
from itertools import product
from dangr_types import AngrExpr, Address
from variables import Variable

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

    def bit_size(self) -> int:
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
        return self.variable.reference_address

    @override
    def bit_size(self) -> int:
        return self.variable.bit_size()

class BinaryOpNode(ExpressionNode):
    def __init__(self, lh: ExpressionNode, rh: ExpressionNode):
        self.lh = lh
        self.rh = rh

    @abstractmethod
    def create_expressions(self) -> list[AngrExpr]:
        pass

    @override
    def expression_address(self) -> Address:
        return max(self.lh.expression_address(), self.rh.expression_address())

    @override
    def bit_size(self) -> int:
        size = self.lh.bit_size()

        if size != self.rh.bit_size():
            raise ValueError("Mismatch of expression sizes")

        return size

class EqualNode(BinaryOpNode):
    @override
    def create_expressions(self) -> list[AngrExpr]:
        return [
            lh == rh for lh, rh in 
            product(self.lh.create_expressions(), self.rh.create_expressions())
        ]


class SumNode(BinaryOpNode):
    @override
    def create_expressions(self) -> list[AngrExpr]:
        return [
            lh + rh for lh, rh in 
            product(self.lh.create_expressions(), self.rh.create_expressions())
        ]

class MultNode(BinaryOpNode):
    @override
    def create_expressions(self) -> list[AngrExpr]:
        return [
            lh * rh for lh, rh in
            product(self.lh.create_expressions(), self.rh.create_expressions())
        ]
