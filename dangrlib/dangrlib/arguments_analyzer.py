from typing import Final
import angr
from variables import ConcreteState, Variable
from simulation_manager import BackwardSimulation, ForwardSimulation
from dangr_types import Address

class ArgumentsAnalyzer:
    """
    This class is responsible for obtaining the concrete values of registers in a given project.
    Implements the method `solve_registers`.
    """
    def __init__(
        self,
        project: angr.Project,
        cfg: angr.analyses.CFGFast,
        max_depth: int | None = None
    ) -> None:
        self.project: Final = project
        self.cfg: Final = cfg
        self.max_depth = max_depth

    def get_fn_args(self, hints: list[Variable], fn_addr: Address) -> list[Variable]:
        """
        Returns the arguments used in the function from address `fn_addr`
        The hints say which variables are relevant to the analysis
        """
        simulator = ForwardSimulation(self.project, fn_addr)
        dependencies = []
        for hint in hints:
            states = simulator.simulate(target=hint.reference_address)
            hint.set_ref_state(states)
            dependencies.extend(hint.dependencies())
        return dependencies

    def solve_arguments(self, fn_addr: Address, args: list[Variable]) -> list[ConcreteState]:
        """
        Obtain the concrete values of the `registers` in the function at `fn_address`.
        Uses a "backwards simulation" to find the values of the registers.

        Args:
            fn_address (Address): The address of the function to find the values of the registers
            registers (list[Register]): The registers to find the values of

        Returns:
            list[ConcreteState]: The values of the registers in the function for each path
            to that function
        """
        if not args:
            return [ConcreteState()]

        simulator = BackwardSimulation(self.project, self.cfg, args, self.max_depth)
        found_states = simulator.simulate(fn_addr)
        return [self._get_args_values(args, state) for state in found_states]

    def _get_args_values(self, args: list[Variable], state: angr.SimState) -> ConcreteState:
        concrete_state = ConcreteState()
        for arg in args:
            arg.set_ref_state([state])
            if arg.is_concrete():
                concrete_state.add_value(arg, value=arg.evaluate()[state])
        return concrete_state
