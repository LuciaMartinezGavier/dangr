"""
This module defines a set of classes representing variables in symbolic execution
using the angr framework.

Classes:
- Variable: An abstract base class for variables involved in symbolic execution.
    - Register: Represents a CPU register and its symbolic representation.
    - Memory: Represents a memory location and its symbolic representation.
    - Literal: Represents a constant literal value in symbolic execution.
    - Deref: Represents a dereference operation in symbolic execution.

- VariableFactory: A factory class for creating Variable objects.
- Argument: A data class representing an argument in a function call.
- ConcreteState: A class for mapping variables to their concrete values.

"""

from abc import abstractmethod, ABC
from dataclasses import dataclass
from functools import wraps
from typing import override, ItemsView, Final
import angr
import claripy

from dangrlib.jasm_findings import CaptureInfo
from dangrlib.dangr_types import Address, AngrExpr, BYTE_SIZE


class Variable(ABC):
    """
    An abstract base class representing a variable.

    This class is used to represent variables like registers, memory, or literals
    that can participate in symbolic execution.
    """

    @staticmethod
    def ref_state_is_set(method): # type: ignore[no-untyped-def]
        """
        Checks that `self.reference_states` is not None, if it is, raises a `ValueError`
        """
        @wraps(method)
        def wrapper(self, *args, **kwargs): # type: ignore[no-untyped-def]
            if self.reference_states is None:
                raise ValueError(f"reference_states is None in {self.__class__.__name__}")
            return method(self, *args, **kwargs)
        return wrapper

    def __init__(self, project, ref_addr: Address):
        self.project: Final = project
        self.ref_addr: Final = ref_addr
        self.reference_states: list[angr.SimState] | None = None

    @abstractmethod
    def set_ref_state(self, states: list[angr.SimState]) -> None:
        """
        Set the states asociated to the variable
        """

    @abstractmethod
    def angr_repr(self) -> dict[angr.SimState, AngrExpr]:
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

    @ref_state_is_set
    def dependencies(self, variable_factory) -> list['Variable']:
        """
        Calculates the dependencies of this variable across multiple symbolic states.

        Returns:
            list[Variable]: A list of variables that this variable depends on.
        """
        deps: set[Variable] = set()

        for ref_state in self.reference_states: # type: ignore[union-attr]
            state_variables: set[str] = getattr(self.angr_repr()[ref_state], 'variables', set())

            deps.update({
                variable_factory.create_from_angr_name(var_name, self.ref_addr)
                for var_name in state_variables
            })

        return list(deps)

    @ref_state_is_set
    def evaluate(self) -> dict[angr.SimState, int]:
        """
        Evaluates the current variable in the symbolic states where it is referenced.

        Returns:
            int: The concrete value of the variable.
        """
        return {
            state: state.solver.eval(self.angr_repr()[state], cast_to=int)
            for state in self.reference_states # type: ignore[union-attr]
        }

    @ref_state_is_set
    def is_concrete(self) -> bool:
        """
        Checks if the variable has a concrete value in the given symbolic state.

        Arguments:
            state (angr.SimState): The symbolic state of the program.

        Returns:
           list[bool]: True if the variable is concrete for each state.
        """
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
    def __init__(self, project, reg_name: str, ref_addr: Address):
        super().__init__(project, ref_addr)
        self.name: Final = reg_name

    @override
    def set_ref_state(self, states: list[angr.SimState]) -> None:
        self.reference_states = states

    @override
    @Variable.ref_state_is_set
    def angr_repr(self) -> dict[angr.SimState, AngrExpr]:
        return {
            state: getattr(state.regs, self.name)
            for state in self.reference_states # type: ignore[union-attr]
        }

    @override
    @Variable.ref_state_is_set
    def set_value(self, value: int) -> None:
        for state in self.reference_states: # type: ignore[union-attr]
            setattr(state.regs, self.name, value)

    @override
    def size(self) -> int:
        return self.project.arch.get_register_by_name(self.name).size

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Register):
            return self.name == other.name and self.ref_addr == other.ref_addr
        return False

    def __hash__(self) -> int:
        return hash((self.name, self.ref_addr))

    def normalized_name(self) -> str:
        """
        Normalize the x86-64 register name to its 64-bit equivalent.
        """
        return self.project.arch.get_register_by_name(self.name).name

class Memory(Variable):
    """
    A class representing a memory location in symbolic execution.

    Attributes:
        addr (int): The memory address.
        size (int): The size of the memory region.
    """
    def __init__(self, project, addr: int, size: int, ref_addr: Address) -> None:
        super().__init__(project, ref_addr)
        self._size: Final = size
        self.addr: Final = addr

    @override
    @Variable.ref_state_is_set
    def angr_repr(self) -> dict[angr.SimState, AngrExpr]:
        return {
            state: state.memory.load(self.addr, self.size())
            for state in self.reference_states
        }

    @override
    def set_ref_state(self, states: list[angr.SimState]) -> None:
        self.reference_states = states

    @override
    @Variable.ref_state_is_set
    def set_value(self, value: int) -> None:
        for state in self.reference_states: # type: ignore[union-attr]
            state.memory.store(self.addr, value, self.size())

    @override
    def size(self) -> int:
        return self._size

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Memory):
            return self.addr == other.addr and \
                   self._size == other._size
        return False

    def __hash__(self) -> int:
        return hash((self.addr, self.size, self.ref_addr))


class Literal(Variable):
    """
    A class representing a literal constant value.

    Attributes:
        value (int): The literal value.
    """
    def __init__(self, project, value: int, ref_addr: int) -> None:
        super().__init__(project, ref_addr)
        self.value: Final = value

    @override
    @Variable.ref_state_is_set
    def angr_repr(self) -> dict[angr.SimState, AngrExpr]:
        return {
            state: claripy.BVV(self.value, self.size()*BYTE_SIZE)
            for state in self.reference_states # type: ignore[union-attr]
        }

    @override
    def set_ref_state(self, states: list[angr.SimState]) -> None:
        self.reference_states = states

    @override
    def set_value(self, value: int) -> None:
        raise ValueError("Can't set a value to a Literal")

    @override
    def size(self) -> int:
        return self.project.factory.block(self.ref_addr).capstone.insns[0].insn.imm_size

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Literal):
            return self.value == other.value
        return False

    def __hash__(self) -> int:
        return hash((self.value))

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
        idx: int = 0
    ) -> None:

        super().__init__(base.project, base.ref_addr)
        self.base: Final = base
        self.idx: Final = idx

    @override
    @Variable.ref_state_is_set
    def angr_repr(self) -> dict[angr.SimState, AngrExpr]:
        return {
            state: state.memory.load(self.base.angr_repr()[state], int(self.size()))
            for state in self.reference_states # type: ignore[union-attr]
        }

    @override
    def set_ref_state(self, states: list[angr.SimState]) -> None:
        self.reference_states = states
        self.base.reference_states = states

    @override
    @Variable.ref_state_is_set
    def set_value(self, value: int) -> None:
        for state in self.reference_states: # type: ignore[union-attr]
            state.memory.store(self.base.angr_repr()[state], value, int(self.size()))

    @Variable.ref_state_is_set
    def evaluate_memory(self, state: angr.SimState) -> list[int]:
        """
        Evaluates the memory referenced by the `self.base` register
        in the given `state` 

        Returns:
            int: The concrete values of the variable.
        """
        return [
            state.solver.eval(
                state.memory.load(self.base.angr_repr()[der_state],
                self.size())
            )
            for der_state in self.reference_states # type: ignore[union-attr]
        ]

    @override
    def size(self) -> int:
        return self.project.factory.block(self.ref_addr).capstone.insns[0].insn.operands[0].size

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Deref):
            return self.base == other.base and self.idx == other.idx
        return False

    def __hash__(self) -> int:
        return hash((self.base, self.idx))


@dataclass
class Argument:
    """
    A data class representing an argument in a function call.
    """
    idx: int
    call_address: int


class VariableFactory:
    """
    A factory class for creating Variable objects (Register, Memory, or Literal).
    """
    REGISTER_MAP = {
        1: 'rdi',
        2: 'rsi',
        3: 'rdx',
        4: 'rcx',
        5: 'r8',
        6: 'r9',
    }

    def __init__(self, project) -> None:
        self.project: Final = project

    def create_from_capture(self, capture: CaptureInfo) -> Variable:
        """
        Creates a Variable from the structural match info.
        """
        match capture.captured:
            case int():
                return Literal(self.project, capture.captured, capture.address)
            case str():
                return Register(self.project, capture.captured, capture.address)
            case _:
                raise ValueError(f"Unsupported capture type: {type(capture.captured)}")

    def create_from_argument(self, argument: Argument) -> Variable:
        """
        Creates a Variable from a function argument based on its index.

        Arguments:
            argument (Argument): The function argument.

        Returns:
            Variable: The corresponding Register variable.

        Raises:
            ValueError: If the argument index does not map to a register.
        """
        register_name = self.REGISTER_MAP.get(argument.idx)

        if register_name is None:
            raise ValueError(f"No register for argument index {argument.idx}")

        return Register(self.project, register_name, argument.call_address)

    def create_from_angr_name(self, angr_name: str, ref_addr: Address) -> Variable:
        """
        Create the Register or Memory object by parsing the name that angr provides
        when obtaining the variables of the symbolic formula.

        Examples:
        >>> Register.angr_name_to_register('reg_rdx_507_64', 0x401111)
        Register(name='rdx', 0x401111)

        >>> Memory.angr_name_to_register('mem_ffffe00000000000_17_32', 0x401111)
        Memory(addr=0xffffe00000000000, size=4, 0x401111)
        """

        if angr_name.startswith("reg"):
            name = angr_name.split("_")[1]
            return Register(self.project, name, ref_addr)

        if angr_name.startswith("mem"):
            _, addr_str, _, size = angr_name.split("_")
            return Memory(self.project, int(addr_str, 16), int(int(size)/8), ref_addr)

        raise ValueError("Unknown variable name")


class ConcreteState:
    """
    A class representing a concrete state in symbolic execution,
    mapping variables to concrete values.
    """

    def __init__(self) -> None:
        self.concrete_state: dict[Variable, int] = {}

    def add_value(self, variable: Variable, value: int) -> None:
        """
        Adds or updates the concrete value associated with a variable.

        Args:
            variable (Variable): The variable to associate with a concrete value.
            value (int): The concrete value to assign to the variable.
        """
        self.concrete_state[variable] = value

    def get_items(self) -> ItemsView[Variable, int]:
        """
        Returns all variable-value pairs in the concrete state.

        Returns:
            ItemsView[Variable, int]: A view of all items (variable-value pairs) in the
            concrete state.
        """
        return self.concrete_state.items()

    def get_value(self, variable: Variable) -> int:
        """
        Retrieves the concrete value associated with a variable.

        Args:
            variable (Variable): The variable whose concrete value is being retrieved.

        Returns:
            int: The concrete value associated with the variable.
        """
        return self.concrete_state[variable]
