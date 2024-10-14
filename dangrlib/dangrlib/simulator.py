from abc import ABC, abstractmethod
from typing import override, Final, Callable
from dataclasses import dataclass
from copy import deepcopy
from angr import SimState, SimulationManager, BP_AFTER, Project
from angr.analyses import CFGFast

from dangrlib.variables import Variable
from dangrlib.dangr_types import Address, CFGNode
ConcreteState = dict['Variable', int]

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
    def __init__(self, project: Project) -> None:
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

        for var, value in self.initial_values.items():
            var.set_ref_states([state])
            var.set_value(value)

        return state

    def set_initial_values(self, initial_values: ConcreteState) -> None:
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
    def __init__(self, project: Project, init_addr: Address, target: Address) -> None:
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

    def __init__(self, project: Project, init_addr: Address) -> None:
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
    current_depth: int
    backup_state: SimState | None
    path: list[CFGNode]

class BackwardSimulation(Simulator):
    """
    Simualte backwards until variables are concrete
    """
    def __init__(
        self, project: Project, target: Address,
        cfg: CFGFast, variables: list[Variable],
        max_depth: int | None = None
    ) -> None:

        super().__init__(project)
        self.target = target
        self.cfg = cfg
        self.variables = variables
        self.states_found: list[SimState] = []
        self.max_depth: Final = max_depth or 1

    @override
    def simulate(self) -> list[SimState]:
        target_node = self.cfg.model.get_any_node(self.target)

        if target_node is None:
            raise ValueError("Target node not found")

        rec_ctx = RecursiveCtx(0, None, [target_node])
        self._rec_simulate(target_node, rec_ctx)
        return self.states_found

    def _node_addr(self, node: CFGNode) -> Address:
        if not isinstance(node.addr, int):
            raise ValueError(f"Unsupported node {node}")
        return node.addr

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

        state = self._simulate_slice(self._node_addr(initial_node), target_node, rec_ctx.path)

        if not state:
            if rec_ctx.backup_state:
                self.states_found.append(rec_ctx.backup_state)
            return

        for var in self.variables:
            var.set_ref_states([state])

        if all(var.is_concrete() for var in self.variables) or\
           rec_ctx.current_depth >= self.max_depth:
            self.states_found.append(state)
            return

        for pred in [p for p in self.cfg.model.get_predecessors(initial_node)]:
            new_rec_ctx = RecursiveCtx(rec_ctx.current_depth + 1, state, rec_ctx.path + [pred])
            self._rec_simulate(target_node, new_rec_ctx)

    def _simulate_slice(
        self,
        start: Address,
        target_node: CFGNode,
        pred: list[CFGNode],
    ) -> SimState | None:

        initial = self._initialize_state(start)
        simgr = self.project.factory.simulation_manager(initial)
        state_found = self._get_finding(simgr, self._node_addr(target_node))

        while simgr.active and not state_found:
            self._remove_states(simgr.active, pred)
            simgr.step()
            state_found = self._get_finding(simgr, self._node_addr(target_node))

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
        return not is_in_slice or is_external_block or already_visited

class HookSimulation(Simulator):
    """
    Simulate until reaching a target
    """
    def __init__(
        self,
        project: Project,
        init_addr: Address,
        event: str,
        action: Callable[[SimState], None],
        when: str, # angr constant BP_BEFORE | BP_AFTER | BP_BOTH
        stop: Callable[[list[SimState]], bool],
        condition: Callable[[SimState], bool] | None = None
    ) -> None:

        super().__init__(project)
        self.init_addr = init_addr
        self.event = event
        self.action = action
        self.when = when
        self.stop = stop
        self.condition = condition
    @override
    def simulate(self) -> list[SimState]:
        initial = self._initialize_state(self.init_addr)
        simulation = self.project.factory.simulation_manager(initial)
        initial.inspect.b(self.event, action=self.action, when=self.when, condition=self.condition)

        while simulation.active and not self.stop(simulation.active):
            simulation.step()

        return simulation.active
