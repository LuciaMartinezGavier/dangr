from abc import ABC, abstractmethod
from typing import override, Final
from dataclasses import dataclass
from angr import SimState, SimulationManager
from variables import ConcreteState, Variable
from dangr_types import Address, CFGNode

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

    def initialize_state(self, concrete_state: ConcreteState | None, state: SimState) -> None:
        """"
        Sets the initial values from concrete_state in the given state
        Modifies state
        """
        if concrete_state is None:
            return

        for var, value in concrete_state.get_items():
            var.set_ref_state([state])
            var.set_value(value)

    @abstractmethod
    def simulate(
        self,
        target: Address,
        concrete_state: ConcreteState | None = None
    ) -> list[SimState]:
        """
        Excecutes simbolically until reaching the target.

        Arguments:
            target (Address): the target to find
            concrete_state (ConcreteState): the values to initialize the simulation

        Returns
            list[SimState]: the list of states on which the target was found

        """


class ForwardSimulation(Simulator):
    """
    Simulate until reaching a target
    """
    def __init__(self, project, init_addr) -> None:
        super().__init__(project)
        self.init_addr = init_addr

    @override
    def simulate(
        self,
        target: Address,
        concrete_state: ConcreteState | None = None
    ) -> list[SimState]:
        """
        Excecutes simbolically from `self.init_addr` until reaching the target.

        Arguments:
            target (Address): the target to find
            concrete_state (ConcreteState): the values to initialize the simulation

        Returns
            list[SimState]: the list of states on which the target was found

        """
        initial_state = self.project.factory.blank_state(addr=self.init_addr)
        self.initialize_state(concrete_state, initial_state)
        simulation = self.project.factory.simulation_manager(initial_state)
        simulation.explore(find=target)
        return simulation.found


class StepSimulation(Simulator):
    """
    Simulates a chunk of a binary from the init_addr until the first address is met.
    The simulation can be resumed from the previous state.
    """

    def __init__(self, project, init_addr) -> None:
        super().__init__(project)
        self.init_addr = init_addr
        self.previous_states: list[SimState] | SimState | None = None

    def simulate(
        self,
        target: Address,
        concrete_state: ConcreteState | None = None
    ) -> list[SimState]:

        if self.previous_states is None:
            initial_state = self.project.factory.blank_state(addr=self.init_addr)
            self.initialize_state(concrete_state, initial_state)
            self.previous_states = initial_state

        simulation = self.project.factory.simulation_manager(self.previous_states)
        simulation.explore(find=target)
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
    def __init__(self, project, cfg, variables: list[Variable], max_depth: int | None) -> None:
        super().__init__(project)
        self.cfg = cfg
        self.variables = variables
        self.states_found: list[SimState] = []
        self.max_depth: Final = max_depth if max_depth else 2

    @override
    def simulate(
        self,
        target: Address,
        concrete_state: ConcreteState | None = None
    ) -> list[SimState]:

        target_node = self.cfg.get_any_node(target)
        rec_ctx = RecursiveCtx(0, None, [target_node])
        self._rec_simulate(target_node, concrete_state, rec_ctx)
        return self.states_found

    def _rec_simulate(
        self,
        target_node: CFGNode,
        initial_values: ConcreteState | None,
        rec_ctx: RecursiveCtx
    ) -> None:
        """
        Simulate the execution of the program until reaching the `function_node`, the simulation
        is done on the `path` and starts on the last node of the path.
        
        It will recursively look for the path that makes the `registers` concrete and when found
        it returns the concrete values of the registers in that path.
        """
        initial_node = rec_ctx.path[-1]
        state = self._simulate_slice(initial_node.addr, target_node, rec_ctx.path, initial_values)

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
            self._rec_simulate(target_node, initial_values, rec_ctx)


    def _simulate_slice(
        self,
        start: Address,
        target_node: CFGNode,
        pred: list[CFGNode],
        initial_concrete_state: ConcreteState | None
    ) -> SimState | None:

        initial_state = self.project.factory.blank_state(addr=start)
        self.initialize_state(initial_concrete_state, initial_state)
        simgr = self.project.factory.simulation_manager(initial_state)
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
