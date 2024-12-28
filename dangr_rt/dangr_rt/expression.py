from typing import override
from abc import ABC, abstractmethod
import claripy
from dangr_rt.dangr_types import AngrExpr, Address, BYTE_SIZE, AngrBool, AngrArith
from dangr_rt.variables import Variable

class Expression[TypeResult](ABC):
    """
    Represents an expression. It can be boolean or arithmetic
    """
    @abstractmethod
    def get_expr(self) -> TypeResult:
        """
        Returns a list of the possible angr representations of this expression
        """

    @property
    @abstractmethod
    def ref_addr(self) -> Address | None:
        """
        Returns the reference address in the binary of the expression.
        It is calculated as the address of the atom with the last reference or
        None if the expression is all based on constants that do not appear in the binary 
        """

    def _operand_expr(self, operand):
        return getattr(operand, 'get_expr', lambda: operand)()

    @abstractmethod
    def _to_str(self) -> str:
        pass

    def __repr__(self) -> str:
        return self._to_str()

class Binary[TypeLeft, TypeRight, TypeResult](Expression[TypeResult]):
    """
    Abstract class that represents a binary expression
    """
    def __init__(
        self,
        lhs: Expression[TypeLeft] | Variable | int | bool,
        rhs: Expression[TypeRight] | Variable | int | bool,
        op: str
    ):
        self.op: str = op
        self.lhs = lhs
        self.rhs = rhs

    @override
    @property
    def ref_addr(self) -> Address | None:
        lhs_addr: int | None = getattr(self.lhs, 'ref_addr', None)
        rhs_addr: int | None = getattr(self.rhs, 'ref_addr', None)

        if lhs_addr is None:
            return rhs_addr
        if rhs_addr is None:
            return lhs_addr

        return max(lhs_addr, rhs_addr)

    @override
    def _to_str(self) -> str:
        return f'({self.lhs!r} {self.op} {self.rhs!r})'

class Eq(Binary[AngrExpr, AngrExpr, AngrBool]):
    """
    Eq(lhs, rhs) represents the constraint (lhs == rhs)
    """
    def __init__(
        self,
        lhs: Expression[AngrExpr] | Variable | int | bool,
        rhs: Expression[AngrExpr] | Variable | int | bool
    ):
        super().__init__(lhs, rhs, op='==')

    @override
    def get_expr(self) -> AngrBool:
        return self._operand_expr(self.lhs) == self._operand_expr(self.rhs)

class And(Binary[AngrBool, AngrBool, AngrBool]):
    """
    And(lhs, rhs) represents the constraint (lhs && rhs)
    """
    def __init__(self, lhs: Expression[AngrBool] | bool, rhs: Expression[AngrBool] | bool):
        super().__init__(lhs, rhs, op='&')

    @override
    def get_expr(self) -> AngrBool:
        return claripy.And(self._operand_expr(self.lhs), self._operand_expr(self.rhs))

class Or(Binary[AngrBool, AngrBool, AngrBool]):
    """
    Or(lhs, rhs) represents the constraint (lhs | rhs)
    """
    def __init__(self, lhs: Expression[AngrBool] | bool, rhs: Expression[AngrBool] | bool):
        super().__init__(lhs, rhs, op='|')

    @override
    def get_expr(self) -> AngrBool:
        return claripy.Or(self._operand_expr(self.lhs), self._operand_expr(self.rhs))

class Not(Expression[AngrBool]):
    """
    Not(operand) represents the constraint ~operand
    """
    def __init__(self, operand: Expression[AngrBool] | bool) -> None:
        self.operand = operand

    @override
    def get_expr(self) -> AngrBool:
        return claripy.Not(self._operand_expr(self.operand))

    @override
    @property
    def ref_addr(self) -> Address | None:
        return getattr(self.operand, 'ref_addr', None)

    @override
    def _to_str(self) -> str:
        return f'~{self.operand!r}'

class Add(Binary[AngrArith, AngrArith, AngrArith]):
    """
    Add(lhs, rhs) represents the operation lhs + rhs
    """
    def __init__(
        self,
        lhs: Expression[AngrArith] | Variable | int,
        rhs: Expression[AngrArith] | Variable | int
    ) -> None:
        super().__init__(lhs, rhs, op='+')

    @override
    def get_expr(self) -> AngrArith:
        return self._operand_expr(self.lhs) + self._operand_expr(self.rhs)

class Mul(Binary[AngrArith, AngrArith, AngrArith]):
    """
    Mul(lhs, rhs) represents the operation lhs + rhs
    """
    def __init__(
        self,
        lhs: Expression[AngrArith] | Variable | int,
        rhs: Expression[AngrArith] | Variable | int
    ) -> None:
        super().__init__(lhs, rhs, op='*')

    @override
    def get_expr(self) -> AngrArith:
        return self._operand_expr(self.lhs) * self._operand_expr(self.rhs)

class Sub(Binary[AngrArith, AngrArith, AngrArith]):
    """
    Sub(lhs, rhs) represents the operation lhs - rhs
    """
    def __init__(
        self,
        lhs: Expression[AngrArith] | Variable | int,
        rhs: Expression[AngrArith] | Variable | int
    ) -> None:
        super().__init__(lhs, rhs, op='-')

    @override
    def get_expr(self) -> AngrArith:
        return self._operand_expr(self.lhs) - self._operand_expr(self.rhs)

class Div(Binary[AngrArith, AngrArith, AngrArith]):
    """
    Div(lhs, rhs) represents the operation lhs // rhs (integer division)
    """
    def __init__(
        self,
        lhs: Expression[AngrArith] | Variable | int,
        rhs: Expression[AngrArith] | Variable | int
    ) -> None:
        super().__init__(lhs, rhs, op='//')

    @override
    def get_expr(self) -> AngrArith:
        return self._operand_expr(self.lhs) // self._operand_expr(self.rhs)

class IsMax(Expression[AngrBool]):
    """
    IsMax(operand) represents the constraint operand == <operand max value>
    """
    def __init__(self, operand: Expression[AngrArith]):
        self.operand = operand

    def _size(self, angr_exp: AngrArith) -> int:
        if isinstance(angr_exp, (int, bool)):
            raise ValueError("Can't calculate the max value of an int or bool", angr_exp)

        return angr_exp.size()

    @override
    def get_expr(self) -> AngrBool:
        exp = self.operand.get_expr()
        return exp == 2**(self._size(exp)*BYTE_SIZE) - 1

    @override
    @property
    def ref_addr(self) -> Address | None:
        return self.operand.ref_addr

    @override
    def _to_str(self) -> str:
        return f'IsMax({self.operand!r})'
