from typing import Final, Sequence, cast
from collections import namedtuple
import angr
from dangr_rt.variables import Register
from dangr_rt.simulator import BackwardSimulation, HookSimulation, ConcreteState
from dangr_rt.dangr_types import Address, RegOffset

RegInfo = namedtuple('RegInfo', ['size', 'addr'])
SimRegArg = angr.calling_conventions.SimRegArg

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
        self._args_info: dict[RegOffset, RegInfo | None] = {}

    def get_fn_args(self, fn_addr: Address) -> Sequence[Register]:
        """
        Returns the arguments of the function from address `fn_addr`
        """
        args = self._get_args(fn_addr)
        self._init_args_info(args)

        HookSimulation(
            project=self.project,
            init_addr=fn_addr,
            stop=lambda sts: all(self._args_info.values()),
            event_type='reg_read',
            action=self._record_reg_read,
            when=angr.BP_BEFORE,
        ).simulate()

        return self._create_arg_regs()

    def _create_arg_regs(self) -> Sequence[Register]:
        found_args = []
        for offset, found_info in self._args_info.items():
            if found_info is None:
                raise ValueError("Argument couldn't be found")

            reg_name = self.project.arch.register_size_names[offset, found_info.size]
            found_args.append(Register(self.project, reg_name, found_info.addr))
        return found_args

    def _get_args(self, fn_addr: Address) -> list[SimRegArg]:
        func = self.cfg.functions.get(fn_addr)
        self.project.analyses.VariableRecoveryFast(func)
        cca = self.project.analyses.CallingConvention(func, self.cfg.model, analyze_callsites=True)

        if cca.cc is None:
            raise ValueError("Unsupported calling convention")

        args = cca.cc.arg_locs(cca.prototype)

        for arg in args:
            if not isinstance(arg, SimRegArg):
                raise TypeError(f"Unsupported argument {arg}")

        return cast(list[SimRegArg], args)

    def _init_args_info(self, args: list[SimRegArg]) -> None:
        for arg in args:
            offset: int = arg.check_offset(self.project.arch) # type: ignore [no-untyped-call]
            self._args_info[offset] = None

    def _record_reg_read(self, state: angr.SimState) -> None:
        """Record the instruction address of the first read of the register."""
        addr = self._record_addr(state)
        offset = self._record_offset(state)

        if offset in self._args_info and self._args_info[offset] is None:
            block = state.block(addr) # type: ignore [no-untyped-call]
            size = block.capstone.insns[0].insn.operands[0].size
            self._args_info[offset] = RegInfo(size, addr)

    def _record_addr(self, state: angr.SimState) -> Address:
        if hasattr(state.inspect, 'instruction'):
            return Address(state.inspect.instruction)
        raise ValueError("Instruction address couldn't be found")

    def _record_offset(self, state: angr.SimState) -> RegOffset:
        if hasattr(state.inspect, 'reg_read_offset'):
            return state.solver.eval(state.inspect.reg_read_offset, cast_to=int)
        raise ValueError("Register read offset was not set")


    def solve_arguments(self, fn_addr: Address, args: Sequence[Register]) -> list[ConcreteState]:
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
            variables=list(args),
            max_depth=self.max_depth
        )

        found_states = simulator.simulate()
        return [self._get_args_values(args, state) for state in found_states]

    def _get_args_values(self, args: Sequence[Register], state: angr.SimState) -> ConcreteState:
        concrete_state: ConcreteState = {}
        for arg in args:
            arg.set_ref_state(state)

            if arg.is_concrete():
                concrete_state[arg] = arg.evaluate()
        return concrete_state
