from typing import Final
import angr
from dangr_rt.jasm_findings import VariableMatch
from dangr_rt.dangr_types import Argument
from dangr_rt.variables import Variable, Register, Literal, Deref

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

    def __init__(self, project: angr.Project) -> None:
        self.project: Final = project

    def create_from_capture(self, var: VariableMatch) -> Variable:
        """
        Creates a Variable from the structural match info.
        """
        match var.value:
            case int():
                return Literal(self.project, var.value, var.addr)
            case str():
                return Register(self.project, var.value, var.addr)
            case _:
                raise ValueError(f"Unsupported matched type: {type(var.value)} for {var.name}")

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
        norm_name = self.REGISTER_MAP.get(argument.idx)
        if norm_name is None:
            raise ValueError(f"No register for argument index {argument.idx}")

        offset = self.project.arch.get_register_offset(norm_name) # type: ignore [no-untyped-call]
        reg_name = self.project.arch.register_size_names[offset, argument.size]

        return Register(self.project, reg_name, argument.call_address)

    def create_deref(
        self,
        base: Variable,
        idx: int = 0,
        reverse: bool | None = None
    ) -> Deref:
        """
        Creates a Deref from another register 
        """
        if not isinstance(base, Register):
            raise ValueError("It's only possible to dereference registers")

        return Deref(base, idx=idx, reverse=reverse)
