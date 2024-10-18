from typing import Final, Tuple
import angr
from dangr_rt.variables import Variable, Register
from dangr_rt.simulator import BackwardSimulation, HookSimulation, ConcreteState
from dangr_rt.dangr_types import Address, RegOffset


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
        self.first_read_addrs: dict[RegOffset, Tuple[int, Address] | None] = {}

    def get_fn_args(self, fn_addr: Address) -> list[Variable]:
        """
        Returns the arguments of the function from address `fn_addr`
        """
        func = self.cfg.functions.get(fn_addr)
        self.project.analyses.VariableRecoveryFast(func)
        cca = self.project.analyses.CallingConvention(func, self.cfg.model, analyze_callsites=True)

        if cca.cc is None:
            raise ValueError("Unsupported calling convention")

        args = cca.cc.arg_locs(cca.prototype)

        for arg in args:
            if not isinstance(arg, angr.calling_conventions.SimRegArg):
                raise TypeError(f"Unsupported argument {arg}")

            self.first_read_addrs[arg.check_offset(self.project.arch)] = None

        h_simulator = HookSimulation(
            project=self.project,
            init_addr=fn_addr,
            event='reg_read',
            action=self._record_reg_read,
            when=angr.BP_BEFORE,
            stop=lambda sts: all(self.first_read_addrs.values())
        )

        h_simulator.simulate()

        found_args: list[Variable] = []
        for offset, found_info in self.first_read_addrs.items():

            if found_info is None:
                raise ValueError("Argument couldn't be found")

            size, addr = found_info
            reg_name = self.project.arch.register_size_names[offset, size]

            found_args.append(Register(self.project, reg_name, addr))
        return found_args

    def _record_reg_read(self, state: angr.SimState) -> None:
        """Record the instruction address of the first read of the register."""
        if hasattr(state.inspect, 'instruction'):
            addr = state.inspect.instruction
        else:
            raise ValueError("Instruction address couldn't be found")

        if hasattr(state.inspect, 'reg_read_offset'):
            offset = state.solver.eval(state.inspect.reg_read_offset)
        else:
            raise ValueError("Register read offset was not set")

        if offset in self.first_read_addrs and self.first_read_addrs[offset] is None:
            size = state.block(addr).capstone.insns[0].insn.operands[0].size
            self.first_read_addrs[offset] = (size, addr)


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
            return [{}]

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
        concrete_state = {}
        for arg in args:
            arg.set_ref_states([state])

            if arg.is_concrete():
                concrete_state[arg] = arg.evaluate()[state]
        return concrete_state
