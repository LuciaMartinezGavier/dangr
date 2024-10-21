from typing import override
from abc import ABC, abstractmethod
from itertools import product
from dangr_rt.dangr_types import AngrExpr, Address, BYTE_SIZE, AngrBool, AngrArith
from dangr_rt.variables import Variable

class  Expression(ABC):
    """
    Represents an expression. It can be boolean or arithmetic
    """
    def __init__(self, is_boolean) -> None:
        self.is_boolean = is_boolean

    @abstractmethod
    def get_expr(self) -> list[AngrArith]:
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

    @staticmethod
    def _unique(l: list) -> list:
        return list(set(l))

    @abstractmethod
    def _to_str(self) -> str:
        pass

    def __repr__(self) -> str:
        return self._to_str()


class Binary(Expression):
    """
    Abstract class that represents a binary expression
    """
    def __init__(
        self,
        lhs: Expression | Variable | int | bool,
        rhs: Expression | Variable | int | bool,
        is_boolean: bool,
        op: str
    ):
        super().__init__(is_boolean)
        self.op: str = op
        self.lhs = lhs
        self.rhs = rhs

    @override
    @property
    def ref_addr(self) -> Address:
        lhs_addr = getattr(self.lhs, 'ref_addr', None)
        rhs_addr = getattr(self.rhs, 'ref_addr', None)

        if lhs_addr is None:
            return rhs_addr
        if rhs_addr is None:
            return lhs_addr

        return max(lhs_addr, rhs_addr)

    @override
    def _to_str(self) -> str:
        return f'[{self.lhs!r} {self.op} {self.rhs!r}]'

    def _operands_product(self) -> list[tuple[AngrExpr, AngrExpr]]:
        lhs_exprs = getattr(self.lhs, 'get_expr', lambda: [self.lhs])()
        rhs_exprs = getattr(self.rhs, 'get_expr', lambda: [self.rhs])()

        return product(lhs_exprs, rhs_exprs)

class Eq(Binary):
    """
    Eq(lhs, rhs) represents the constraint (lhs == rhs)
    """
    def __init__(
        self,
        lhs: Expression | Variable | int | bool,
        rhs: Expression | Variable | int | bool
    ):
        super().__init__(lhs, rhs, is_boolean=True, op='==')

    @override
    def get_expr(self) -> list[AngrBool]:
        return self._unique([lh == rh for lh, rh in self._operands_product()])

class And(Binary):
    """
    And(lhs, rhs) represents the constraint (lhs & rhs)
    """
    def __init__(self, lhs: Expression | bool, rhs: Expression | bool):
        super().__init__(lhs, rhs, is_boolean=True, op='&')

    @override
    def get_expr(self) -> list[AngrBool]:
        return self._unique([lh & rh for lh, rh in self._operands_product()])

class Or(Binary):
    """
    Or(lhs, rhs) represents the constraint (lhs | rhs)
    """
    def __init__(self, lhs: Expression | bool, rhs: Expression | bool):
        super().__init__(lhs, rhs, is_boolean=True, op='|')

    @override
    def get_expr(self) -> list[AngrBool]:
        return self._unique([lh | rh for lh, rh in self._operands_product()])

class Not(Expression):
    """
    Not(operand) represents the constraint ~operand
    """
    def __init__(self, operand: Expression | bool) -> None:
        super().__init__(is_boolean=True)
        self.operand = operand

    def _not_expr(self, expr) -> AngrArith:
        return not expr if isinstance(expr, bool) else ~expr

    @override
    def get_expr(self) -> list[AngrArith]:
        return self._unique([self._not_expr(op_expr) for op_expr in self.operand.get_expr()])

    @override
    @property
    def ref_addr(self) -> Address | None:
        return self.operand.ref_addr

    @override
    def _to_str(self) -> str:
        return f'~{self.operand!r}'

class Add(Binary):
    """
    Add(lhs, rhs) represents the operation lhs + rhs
    """
    def __init__(self, lhs: Expression | Variable | int, rhs: Expression | Variable | int) -> None:
        super().__init__(lhs, rhs, is_boolean=False, op='+')

    @override
    def get_expr(self) -> list[AngrArith]:
        return self._unique([lh + rh for lh, rh in self._operands_product()])

class Mul(Binary):
    """
    Mul(lhs, rhs) represents the operation lhs + rhs
    """
    def __init__(self, lhs: Expression | Variable | int, rhs: Expression | Variable | int) -> None:
        super().__init__(lhs, rhs, is_boolean=False, op='*')

    @override
    def get_expr(self) -> list[AngrArith]:
        return self._unique([lh * rh for lh, rh in self._operands_product()])

class Sub(Binary):
    """
    Sub(lhs, rhs) represents the operation lhs - rhs
    """
    def __init__(self, lhs: Expression | Variable | int, rhs: Expression | Variable | int) -> None:
        super().__init__(lhs, rhs, is_boolean=False, op='-')

    @override
    def get_expr(self) -> list[AngrArith]:
        return self._unique([lh - rh for lh, rh in self._operands_product()])

class Div(Binary):
    """
    Div(lhs, rhs) represents the operation lhs // rhs (integer division)
    """
    def __init__(self, lhs: Expression | Variable | int, rhs: Expression | Variable | int) -> None:
        super().__init__(lhs, rhs, is_boolean=False, op='//')

    @override
    def get_expr(self) -> list[AngrArith]:
        return self._unique([lh // rh for lh, rh in self._operands_product()])

class IsMax(Expression):
    """
    IsMax(operand) represents the constraint operand == <operand max value>
    """
    def __init__(self, operand: Expression | int):
        super().__init__(is_boolean=True)
        self.operand = operand

    def _size(self, angr_exp: AngrArith) -> int:
        if isinstance(angr_exp, int) or isinstance(angr_exp, bool):
            raise ValueError("Can't calculate the max value of an int or bool", angr_exp)

        return angr_exp.size()

    def _max_value(self, angr_exp: AngrArith) -> int:
        max_value = 2**self._size(angr_exp)*BYTE_SIZE
        return max_value

    @override
    def get_expr(self) -> list[AngrBool]:
        return self._unique([
            exp == self._max_value(exp) for exp in self.operand.get_expr()
        ])

    @override
    @property
    def ref_addr(self) -> Address:
        return self.operand.ref_addr

    @override
    def _to_str(self) -> str:
        return f'IsMax({self.operand!r})'
