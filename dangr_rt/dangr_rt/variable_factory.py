from typing import Final
import angr
from dangr_rt.jasm_findings import VariableMatch
from dangr_rt.dangr_types import Argument, Address, BYTE_SIZE
from dangr_rt.variables import Variable, Register, Memory, Literal


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
            return Memory(self.project, int(addr_str, 16), int(int(size)/BYTE_SIZE), ref_addr)

        raise ValueError("Unknown variable name")
