from typing import Final
import angr
from variables import ConcreteState, Variable, Register
from simulation_manager import BackwardSimulation, HookSimulation
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
        self.first_read_addrs = {}

    def get_fn_args(self, fn_addr: Address) -> list[Variable]:
        """
        Returns the arguments of the function from address `fn_addr`
        """
        func = self.cfg.functions.get(fn_addr)
        self.project.analyses.VariableRecoveryFast(func)
        cca = self.project.analyses.CallingConvention(func, self.cfg, analyze_callsites=True)

        self.first_read_addrs = {reg.reg_name: None for reg in cca.cc.arg_locs(cca.prototype)}

        h_simulator = HookSimulation(
            project=self.project,
            init_addr=fn_addr,
            event='reg_read',
            action=self._record_reg_read,
            context=self.first_read_addrs,
            when=angr.BP_AFTER,
            stop=lambda ctx: all(ctx.values())
        )

        h_simulator.simulate()
        return [Register(name, addr) for name, addr in self.first_read_addrs.items()]


    def _record_reg_read(self, state: angr.SimState) -> None:
        """Record the instruction address of the first read of the register."""
        offset = state.solver.eval(state.inspect.reg_read_offset)
        reg_name = self.project.arch.translate_register_name(offset)

        if reg_name in self.first_read_addrs and self.first_read_addrs[reg_name] is None:
            self.first_read_addrs[reg_name] = state.addr


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

        simulator = BackwardSimulation(
            project=self.project,
            target=fn_addr,
            cfg=self.cfg,
            variables=args,
            max_depth=self.max_depth
        )

        found_states = simulator.simulate()
        return [self._get_args_values(args, state) for state in found_states]

    def _get_args_values(self, args: list[Variable], state: angr.SimState) -> ConcreteState:
        concrete_state = ConcreteState()
        for arg in args:
            arg.set_ref_state([state])
            if arg.is_concrete():
                concrete_state.add_value(arg, value=arg.evaluate()[state])
        return concrete_state
