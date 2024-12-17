"""
This module defines a set of classes representing variables in symbolic execution
using the angr framework.

Classes:
- Variable: An abstract base class for variables involved in symbolic execution.
    - Register: Represents a CPU register and its symbolic representation.
    - Memory: Represents a memory location and its symbolic representation.
    - Literal: Represents a constant literal value in symbolic execution.
    - Deref: Represents a dereference operation in symbolic execution.

"""

from abc import abstractmethod, ABC
from typing import override, Final
import angr
import claripy
import archinfo

from dangr_rt.dangr_types import Address, BYTE_SIZE


class Variable(ABC):
    """
    An abstract base class representing a variable.

    This class is used to represent variables like registers, memory, or literals
    that can participate in symbolic execution.
    """

    def __init__(self, project: angr.Project, ref_addr: Address) -> None:
        self.project: Final = project
        self.ref_addr: Final = ref_addr
        self.ref_state: angr.SimState | None = None

    @abstractmethod
    def set_ref_state(self, state: angr.SimState) -> None:
        """
        Set the state asociated to the variable
        """

    @abstractmethod
    def get_expr(self) -> claripy.ast.bv.BV:
        """
        Returns an angr compatible representation of the variable
        """

    @abstractmethod
    def set_value(self, value: int) -> None:
        """
        Sets a value to the variable in the symbolic state.

        Arguments:
            state (angr.SimState): The symbolic state of the program.
            value (int): The value to set.
        """

    def evaluate(self) -> int:
        """
        Evaluates the current variable in the symbolic state where it is referenced.

        Returns:
            int: The concrete value of the variable.
        """
        if self.ref_state is None:
            raise ValueError(f"Can't evaluate {self!r} if ref_state is None")

        var_value: int = self.ref_state.solver.eval(self.get_expr(), cast_to=int)
        return var_value

    def is_concrete(self) -> bool:
        """
        Checks if the variable has a concrete value in the symbolic state
        where it is referenced

        Returns:
           bool: True if the variable is concrete.
        """
        if self.ref_state is None:
            raise ValueError(f"Can't check if {self!r} is concrete if ref_state is None")

        return self.get_expr().concrete

    @abstractmethod
    def size(self) -> int:
        """
        Returns the size of the variable in bytes
        """


class Register(Variable):
    """
    A class representing a CPU register in symbolic execution.

    Attributes:
        name (str): The name of the register (e.g., 'rax', 'ebx').
        ref_addr (Address): The address where the register is used.
    """
    def __init__(self, project: angr.Project, reg_name: str, ref_addr: Address) -> None:
        super().__init__(project, ref_addr)
        self.name: Final[str] = reg_name

    @override
    def set_ref_state(self, state: angr.SimState) -> None:
        self.ref_state = state

    @override
    def get_expr(self) -> claripy.ast.bv.BV:
        if self.ref_state is None:
            raise ValueError(f"Can't get expression of {self!r} if ref_state is None")

        return getattr(self.ref_state.regs, self.name) # type: ignore[no-any-return]

    @override
    def set_value(self, value: int) -> None:
        if self.ref_state is None:
            raise ValueError(f"Can't set value of {self!r} if ref_state is None")

        setattr(self.ref_state.regs, self.name, value)

    @override
    def size(self) -> int:
        arch = self.project.arch
        offset = arch.get_register_offset(self.name)  # type: ignore [no-untyped-call]
        possible_sizes = {int(size) for offset, size in arch.register_size_names.keys()}

        size = next(
            i for i in possible_sizes if arch.register_size_names.get((offset, i), '') == self.name
        )
        return size

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Register):
            return self.name == other.name and self.ref_addr == other.ref_addr\
                   and self.project == other.project
        return False

    def __hash__(self) -> int:
        return hash((self.project, self.name, self.ref_addr))

    def __repr__(self) -> str:
        return ('<(x) ' if self.ref_state else '<') +\
                f'Register {self.name} in {hex(self.ref_addr)}>'


class Memory(Variable):
    """
    A class representing a memory location in symbolic execution.
    """
    def __init__( # pylint: disable=(too-many-arguments)
        self,
        project: angr.Project,
        addr: int,
        size: int,
        ref_addr: Address, *,
        reverse: bool | None = None
    ) -> None:

        super().__init__(project, ref_addr)
        self._size: Final[int] = size
        self.addr: Final[Address] = addr
        self.reverse = reverse if reverse is not None else self._default_reverse()

    def _default_reverse(self) -> bool:
        return self.project.arch.memory_endness == archinfo.Endness.LE

    @override
    def get_expr(self) -> claripy.ast.bv.BV:
        if self.ref_state is None:
            raise ValueError(f"Can't get expression of {self!r} if ref_state is None")

        memory = self.ref_state.memory.load(self.addr, self.size())
        return memory.reversed if self.reverse else memory

    @override
    def set_ref_state(self, state: angr.SimState) -> None:
        self.ref_state = state

    @override
    def set_value(self, value: int) -> None:
        if self.ref_state is None:
            raise ValueError(f"Can't set value of {self!r} if ref_state is None")

        bvv_value = claripy.BVV(value, self.size()*BYTE_SIZE)

        if self.reverse:
            bvv_value = bvv_value.reversed

        self.ref_state.memory.store(self.addr, bvv_value, self.size())

    @override
    def size(self) -> int:
        return self._size

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Memory):
            return self.addr == other.addr and \
                   self._size == other._size and\
                   self.project == other.project
        return False

    def __hash__(self) -> int:
        return hash((self.project, self.addr, self.size, self.ref_addr))

    def __repr__(self) -> str:
        return ('<(x) ' if self.ref_state else '<') +\
               f'Memory ({hex(self.addr)}, {self.size()}) reference in {hex(self.ref_addr)}>'


class Literal(Variable):
    """
    A class representing a literal constant value.

    Attributes:
        value (int): The literal value.
    """
    def __init__(
        self, project: angr.Project, value: int,
        ref_addr: int,
        ) -> None:
        super().__init__(project, ref_addr)
        self.value: Final[int] = value

    @override
    def get_expr(self) -> claripy.ast.bv.BV:
        return claripy.BVV(self.value, self.size()*BYTE_SIZE)

    @override
    def set_ref_state(self, state: angr.SimState) -> None:
        pass

    @override
    def set_value(self, value: int) -> None:
        raise ValueError("Can't set a value to a Literal")

    @override
    def size(self) -> int:
        lit_block = self.project.factory.block(self.ref_addr)
        return int(next(op.size for op in lit_block.capstone.insns[0].insn.operands))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Literal):
            return self.value == other.value\
                   and self.project == other.project
        return False

    def __hash__(self) -> int:
        return hash((self.project, self.value))

    def __repr__(self) -> str:
        return f'<Literal {self.value} in {hex(self.ref_addr)}>'

class Deref(Variable):
    """
    A class representing a dereference.

    Attributes:
        value (int): The literal value.

    Right now only the following are supported dereferences:
        movl $0, (%rax)    # indirect (address is in register %rax)
        movl $0, -24(%rbp) # indirect with displacement (address = base %rbp + displacement -24)
    """
    def __init__(
        self,
        base: Register,
        idx: int = 0,
        reverse: bool | None = None
    ) -> None:

        super().__init__(base.project, base.ref_addr)
        self.base: Final[Register] = base
        self.idx: Final[int] = idx
        self.reverse: Final[bool] = reverse if reverse is not None else self._default_reverse()

    def _default_reverse(self) -> bool:
        return self.project.arch.memory_endness == archinfo.Endness.LE

    @override
    def get_expr(self) -> claripy.ast.bv.BV:
        if self.ref_state is None:
            raise ValueError(f"Can't get expression of {self!r} if ref_state is None")

        mem = self.ref_state.memory.load(
            self.base.get_expr(),
            int(self.size())
        )

        return mem.reversed if self.reverse else mem

    @override
    def set_ref_state(self, state: angr.SimState) -> None:
        self.ref_state = state
        self.base.ref_state = state

    @override
    def set_value(self, value: int) -> None:
        if self.ref_state is None:
            raise ValueError(f"Can't set value of {self!r} if ref_state is None")

        bvv_value = claripy.BVV(value, self.size()*BYTE_SIZE)
        if self.reverse:
            bvv_value = bvv_value.reversed

        self.ref_state.memory.store(self.base.get_expr(), bvv_value, self.size())

    @override
    def size(self) -> int:
        deref_block = self.project.factory.block(self.ref_addr)
        return int(deref_block.capstone.insns[0].insn.operands[0].size)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Deref):
            return self.base == other.base and self.idx == other.idx
        return False

    def __hash__(self) -> int:
        return hash((self.base, self.idx))

    def __repr__(self) -> str:
        return f'<Deref ${self.idx} + {self.base!r}>'
