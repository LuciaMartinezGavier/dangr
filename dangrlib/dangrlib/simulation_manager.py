from abc import ABC, abstractmethod
from typing import override, Final
from dataclasses import dataclass
from angr import SimState, SimulationManager, BP_AFTER
from copy import deepcopy

from dangrlib.variables import ConcreteState, Variable
from dangrlib.dangr_types import Address, CFGNode, Context

EXTERNAL_ADDR_SPACE_BASE: Final = 0x500000
ENDBR64_MNEMONIC: Final = 'endbr64'


class Simulator(ABC):
    """
    A manager for symbolic execution simulations using angr. 

    This class is designed to handle symbolic execution.

    Attributes:
        project (angr.Project): The angr project to simulate.
        init_addr (Address): The initial address where the simulation starts.
    """
    def __init__(self, project) -> None:
        self.project = project
        self.initial_values: None | ConcreteState = None

    def _initialize_state(self, start: Address) -> SimState:
        """"
        Sets the initial values from concrete_state in the given state
        Modifies state
        """
        state = self.project.factory.blank_state(addr=start)

        if self.initial_values is None:
            return state

        for var, value in self.initial_values.get_items():
            var.set_ref_state([state])
            var.set_value(value)

        return state

    def set_inital_values(self, initial_values: ConcreteState) -> None:
        """
        Set values for the initial state of the simulation
        """
        self.initial_values = initial_values

    @abstractmethod
    def simulate(self) -> list[SimState]:
        """
        Excecutes simbolically.

        Arguments:
            concrete_state (ConcreteState): the values to initialize the simulation

        Returns
            list[SimState]: the list of states on which the target was found

        """


class ForwardSimulation(Simulator):
    """
    Simulate until reaching a target
    """
    def __init__(self, project, init_addr, target) -> None:
        super().__init__(project)
        self.init_addr = init_addr
        self.target = target

    @override
    def simulate(self) -> list[SimState]:
        found_states = []

        initial = self._initialize_state(self.init_addr)
        simulation = self.project.factory.simulation_manager(initial)

        initial.inspect.b(
            'instruction', when=BP_AFTER, instruction=self.target,
            action=lambda state: found_states.append(deepcopy(state))
        )

        while simulation.active:
            simulation.step()

        return found_states

class StepSimulation(Simulator):
    """
    Simulates a chunk of a binary from the init_addr until the first address is met.
    The simulation can be resumed from the previous state.
    """

    def __init__(self, project, init_addr) -> None:
        super().__init__(project)
        self.init_addr = init_addr

        self.target: Address | None = None
        self.previous_states: list[SimState] | SimState | None = None

    def set_step_target(self, target: Address) -> None:
        self.target = target

    def simulate(self) -> list[SimState]:
        if self.previous_states is None:
            initial = self._initialize_state(self.init_addr)
            self.previous_states = initial

        simulation = self.project.factory.simulation_manager(self.previous_states)
        simulation.explore(find=self.target)
        self.previous_states = simulation.found

        return simulation.found

@dataclass
class RecursiveCtx:
    current_depht: int
    backup_state: SimState | None
    path: list[CFGNode]

class BackwardSimulation(Simulator):
    """
    Simualte backwards until variables are concrete
    """
    def __init__(self, project, target, cfg, variables: list[Variable], max_depth: int | None) -> None:
        super().__init__(project)
        self.target = target
        self.cfg = cfg
        self.variables = variables
        self.states_found: list[SimState] = []
        self.max_depth: Final = max_depth if max_depth else 2

    @override
    def simulate(self) -> list[SimState]:
        target_node = self.cfg.get_any_node(self.target)
        rec_ctx = RecursiveCtx(0, None, [target_node])
        self._rec_simulate(target_node, rec_ctx)
        return self.states_found

    def _rec_simulate(
        self,
        target_node: CFGNode,
        rec_ctx: RecursiveCtx
    ) -> None:
        """
        Simulate the execution of the program until reaching the `function_node`, the simulation
        is done on the `path` and starts on the last node of the path.
        
        It will recursively look for the path that makes the `registers` concrete and when found
        it returns the concrete values of the registers in that path.
        """
        initial_node = rec_ctx.path[-1]
        state = self._simulate_slice(initial_node.addr, target_node, rec_ctx.path)

        if not state or rec_ctx.current_depht >= self.max_depth:
            self.states_found.append(rec_ctx.backup_state)
            return

        for var in self.variables:
            var.set_ref_state([state])

        if all(var.is_concrete() for var in self.variables):
            self.states_found.append(state)
            return

        rec_ctx.backup_state = state
        for pred in [p for p in self.cfg.get_predecessors(initial_node) if p not in rec_ctx.path]:
            rec_ctx.current_depht = rec_ctx.current_depht + 1
            rec_ctx.path = rec_ctx.path + [pred]
            self._rec_simulate(target_node, rec_ctx)


    def _simulate_slice(
        self,
        start: Address,
        target_node: CFGNode,
        pred: list[CFGNode],
    ) -> SimState | None:

        initial = self._initialize_state(start)
        simgr = self.project.factory.simulation_manager(initial)
        state_found: SimState | None = None

        while simgr.active and not state_found:
            state_found = self._get_finding(simgr, target_node.addr)
            self._remove_states(simgr.active, pred)
            simgr.step()

        return state_found

    def _get_finding(self, simgr: SimulationManager, target: Address) -> SimState | None:
        return next((state for state in simgr.active if state.addr == target), None)

    def _remove_states(self, active_states: list[SimState], pred: list[CFGNode]) -> None:
        for state in active_states:
            if self._remove_condition(state, pred):
                active_states.remove(state)

    def _remove_condition(self, state: SimState, pred: list[CFGNode]) -> bool:
        already_visited = state.addr in state.history.bbl_addrs
        is_external_block =  state.addr >= EXTERNAL_ADDR_SPACE_BASE
        is_in_slice = state.addr in [p.addr for p in pred]
        is_start_of_func = state.block().capstone.insns and \
                           state.block().capstone.insns[0].mnemonic == ENDBR64_MNEMONIC

        return already_visited or\
               (not is_external_block and not is_in_slice and not is_start_of_func)

class HookSimulation(Simulator):
    """
    Simulate until reaching a target
    """
    def __init__(
        self,
        project,
        init_addr: Address,
        event: str,
        action,
        context: Context,
        when,
        stop
    ) -> None:

        super().__init__(project)
        self.init_addr = init_addr
        self.event = event
        self.action = action
        self.context = context
        self.when = when
        self.stop = stop

    @override
    def simulate(self) -> list[SimState]:
        """
        Excecutes simbolically from `self.init_addr` until reaching the target.

        Arguments:
            target (Address): the target to find
            concrete_state (ConcreteState): the values to initialize the simulation

        Returns
            list[SimState]: the list of states on which the target was found

        """
        initial = self._initialize_state(self.init_addr)
        simulation = self.project.factory.simulation_manager(initial)
        initial.inspect.b(self.event, action=self.action, when=self.when)

        while simulation.active and not self.stop(self.context):
            simulation.step()

        return simulation.active
