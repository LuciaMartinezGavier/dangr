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

from dangr_rt.dangr_types import Address, AngrExpr, BYTE_SIZE


class Variable(ABC):
    """
    An abstract base class representing a variable.

    This class is used to represent variables like registers, memory, or literals
    that can participate in symbolic execution.
    """

    def _check_ref_state_is_set(self) -> None:
        """
        Checks that `self.reference_states` is not None, if it is, raises a `ValueError`
        """
        if self.reference_states is None:
            raise ValueError(f"reference_states is None in {self!r}")

    def __init__(self, project: angr.Project, ref_addr: Address) -> None:
        self.project: Final = project
        self.ref_addr: Final = ref_addr
        self.reference_states: set[angr.SimState] | None = None

    @abstractmethod
    def set_ref_states(self, states: list[angr.SimState]) -> None:
        """
        Set the states asociated to the variable
        """

    @abstractmethod
    def angr_repr(self) -> dict[angr.SimState | None, AngrExpr]:
        """
        Returns an angr compatible representation given a state
        """

    @abstractmethod
    def set_value(self, value: int) -> None:
        """
        Sets a value to the variable in the symbolic state.

        Arguments:
            state (angr.SimState): The symbolic state of the program.
            value (int): The value to set.
        """

    def dependencies(self, variable_factory: 'VariableFactory') -> list['Variable']: # type: ignore [name-defined]
        """
        Calculates the dependencies of this variable across multiple symbolic states.

        Returns:
            list[Variable]: A list of variables that this variable depends on.
        """
        self._check_ref_state_is_set()
        deps: set[Variable] = set()

        for ref_state in self.reference_states: # type: ignore[union-attr]
            state_variables: set[str] = getattr(self.angr_repr()[ref_state], 'variables', set())

            deps.update({
                variable_factory.create_from_angr_name(var_name, self.ref_addr)
                for var_name in state_variables
            })

        return list(deps)

    def evaluate(self) -> dict[angr.SimState, int]:
        """
        Evaluates the current variable in the symbolic states where it is referenced.

        Returns:
            int: The concrete value of the variable.
        """
        self._check_ref_state_is_set()
        return {
            state: state.solver.eval(self.angr_repr()[state], cast_to=int)
            for state in self.reference_states # type: ignore[union-attr]
        }

    def is_concrete(self) -> bool:
        """
        Checks if the variable has a concrete value in the given symbolic state.

        Arguments:
            state (angr.SimState): The symbolic state of the program.

        Returns:
           list[bool]: True if the variable is concrete for each state.
        """
        self._check_ref_state_is_set()
        return all(
            self.angr_repr()[state].concrete
            for state in self.reference_states # type: ignore[union-attr]
        )

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
        self.name: Final = reg_name

    @override
    def set_ref_states(self, states: list[angr.SimState]) -> None:
        self.reference_states = set(states)

    @override
    def angr_repr(self) -> dict[angr.SimState, AngrExpr]:
        self._check_ref_state_is_set()
        return {
            state: getattr(state.regs, self.name)
            for state in self.reference_states # type: ignore[union-attr]
        }

    @override
    def set_value(self, value: int) -> None:
        self._check_ref_state_is_set()
        for state in self.reference_states: # type: ignore[union-attr]
            setattr(state.regs, self.name, value)

    @override
    def size(self) -> int:
        arch = self.project.arch
        offset = arch.get_register_offset(self.name)
        possible_sizes = set([int(size) for offset, size in arch.register_size_names.keys()])

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

    def normalized_name(self) -> str:
        """
        Normalize the x86-64 register name to its 64-bit equivalent.
        """
        return str(self.project.arch.get_register_by_name(self.name).name)

    def __repr__(self) -> str:
        return ('<(x) ' if self.reference_states else '<') +\
                f'Register {self.name} in {hex(self.ref_addr)}>'


class Memory(Variable):
    """
    A class representing a memory location in symbolic execution.

    Attributes:
        addr (Address): The memory address.
        size (int): The size of the memory region.
    """
    def __init__(self, project: angr.Project, addr: int, size: int, ref_addr: Address) -> None:
        super().__init__(project, ref_addr)
        self._size: Final = size
        self.addr: Final = addr

    @override
    def angr_repr(self) -> dict[angr.SimState, AngrExpr]:
        self._check_ref_state_is_set()
        # TODO: reverse if necesary
        return {
            state: state.memory.load(self.addr, self.size())
            for state in self.reference_states # type: ignore[union-attr]
        }

    @override
    def set_ref_states(self, states: list[angr.SimState]) -> None:
        self.reference_states = set(states)

    @override
    def set_value(self, value: int) -> None:
        self._check_ref_state_is_set()
        for state in self.reference_states: # type: ignore[union-attr]
            state.memory.store(self.addr, value, self.size())

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
        return ('<(x) ' if self.reference_states else '<') +\
               f'Memory ({hex(self.addr)}, {self.size()}) reference in {hex(self.ref_addr)}>'


class Literal(Variable):
    """
    A class representing a literal constant value.

    Attributes:
        value (int): The literal value.
    """
    def __init__(
        self, project: angr.Project, value: int,
        ref_addr: int | None = None,
        size: int | None = None
        ) -> None:

        super().__init__(project, ref_addr or 0)
        self.value: Final = value
        if not size and not ref_addr:
            raise ValueError("Either size of ref_addr should be set")

        self._size = size


    @override
    def angr_repr(self) -> dict[angr.SimState | None, AngrExpr]:
        if self.reference_states:
            return {
                state: claripy.BVV(self.value, self.size()*BYTE_SIZE)
                for state in self.reference_states # type: ignore[union-attr]
            }
        return { None: claripy.BVV(self.value, self.size()*BYTE_SIZE) }

    @override
    def set_ref_states(self, states: list[angr.SimState]) -> None:
        self.reference_states = set(states)

    @override
    def set_value(self, value: int) -> None:
        raise ValueError("Can't set a value to a Literal")

    @override
    def size(self) -> int:
        if not self._size:
            self._size = int(
                self.project.factory.block(self.ref_addr).capstone.insns[0].insn.imm_size
            )
        return self._size

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
        reverse: bool = False
    ) -> None:

        super().__init__(base.project, base.ref_addr)
        self.base: Final = base
        self.idx: Final = idx
        self.reverse: Final = reverse

    def _load_mem(self, state: angr.SimState) -> AngrExpr:
        mem = state.memory.load(self.base.angr_repr()[state], int(self.size()))
        if self.reverse:
            return mem.reversed

        return mem

    @override
    def angr_repr(self) -> dict[angr.SimState, AngrExpr]:
        self._check_ref_state_is_set()
        return {
            state: self._load_mem(state)
            for state in self.reference_states # type: ignore[union-attr]
        }

    @override
    def set_ref_states(self, states: list[angr.SimState]) -> None:
        self.reference_states = set(states)
        self.base.reference_states = set(states)

    @override
    def set_value(self, value: int) -> None:
        self._check_ref_state_is_set()
        for state in self.reference_states: # type: ignore[union-attr]
            state.memory.store(self.base.angr_repr()[state], value, int(self.size()))


    def memory_contents(self, state: angr.SimState, reverse: bool) -> list[AngrExpr]:
        """
        Evaluates the memory referenced by the `self.base` register
        in the given `state` 

        Returns:
            int: The concrete values of the variable.
        """
        self._check_ref_state_is_set()
        memory_contents: list[AngrExpr] = []
        for der_state in self.reference_states: # type: ignore[union-attr]
            memory = state.memory.load(self.base.angr_repr()[der_state], self.size())
            if reverse:
                memory = memory.reversed
            memory_contents.append(memory)
        return memory_contents

    @override
    def size(self) -> int:
        return int(self.project.factory.block(self.ref_addr).capstone.insns[0].insn.operands[0].size)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Deref):
            return self.base == other.base and self.idx == other.idx
        return False

    def __hash__(self) -> int:
        return hash((self.base, self.idx))

    def __repr__(self) -> str:
        return f'<Deref ${self.idx} + {self.base!r}>'
