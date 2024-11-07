from abc import ABC, abstractmethod
from typing import override, Final, Callable, Any
from dataclasses import dataclass
from copy import deepcopy
import angr

from dangr_rt.variables import Variable
from dangr_rt.dangr_types import Address, CFGNode
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
    def __init__(self, project: angr.Project) -> None:
        self.project = project
        self.initial_values: None | ConcreteState = None

    def _initialize_state(
        self,
        start: Address,
        add_options: set[str] | None = None
    ) -> angr.SimState:
        """"
        Sets the initial values from concrete_state in the given state
        Modifies state
        """
        state: angr.SimState = self.project.factory.blank_state( # type: ignore [no-untyped-call]
            addr=start,
            add_options=add_options
        )

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
    def simulate(self) -> list[angr.SimState]:
        """
        Excecutes simbolically.

        Arguments:
            concrete_state (ConcreteState): the values to initialize the simulation

        Returns
            list[angr.SimState]: the list of states on which the target was found

        """


class ForwardSimulation(Simulator):
    """
    Simulate until reaching a target
    """
    def __init__(self, project: angr.Project, init_addr: Address, target: Address) -> None:
        super().__init__(project)
        self.init_addr = init_addr
        self.target = target

    @override
    def simulate(self) -> list[angr.SimState]:
        found_states = []

        initial = self._initialize_state(self.init_addr)
        simulation = self.project.factory.simulation_manager(initial)

        initial.inspect.b( # type: ignore [no-untyped-call]
            'instruction', when=angr.BP_AFTER, instruction=self.target,
            action=lambda state: found_states.append(deepcopy(state))
        )

        while simulation.active:
            simulation.step() # type: ignore [no-untyped-call]

        return found_states

class StepSimulation(Simulator):
    """
    Simulates a chunk of a binary from the init_addr until the first address is met.
    The simulation can be resumed from the previous state.
    """

    def __init__(
        self,
        project: angr.Project,
        init_addr: Address,
        timeout: int | None = None
    ) -> None:

        super().__init__(project)
        self.init_addr = init_addr

        self.target: Address | None = None
        self.previous_states: list[angr.SimState] | angr.SimState | None = None
        self.timeout = timeout

    def set_step_target(self, target: Address) -> None:
        self.target = target

    def simulate(self) -> list[angr.SimState]:
        if self.previous_states is None:
            initial = self._initialize_state(self.init_addr)
            self.previous_states = initial

        simulation = self.project.factory.simulation_manager(self.previous_states)
        timeout_tech = angr.exploration_techniques.Timeout(self.timeout) # type: ignore [no-untyped-call]
        simulation.use_technique(timeout_tech) # type: ignore [no-untyped-call]
        simulation.explore(find=self.target) # type: ignore [no-untyped-call]
        self.previous_states = simulation.found

        return simulation.found

@dataclass
class RecursiveCtx:
    current_depth: int
    backup_state: angr.SimState | None
    path: list[CFGNode]

class BackwardSimulation(Simulator):
    """
    Simualte backwards until variables are concrete
    """
    def __init__( # pylint: disable=too-many-arguments
        self, project: angr.Project, *, target: Address,
        cfg: angr.analyses.CFGFast, variables: list[Variable],
        max_depth: int | None = None
    ) -> None:

        super().__init__(project)
        self.target = target
        self.cfg = cfg
        self.variables = variables
        self.states_found: list[angr.SimState] = []
        self.max_depth: Final = max_depth or 1

    @override
    def simulate(self) -> list[angr.SimState]:
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
            self._handle_no_found_state(rec_ctx)
            return

        self._set_state_to_vars(state)

        if self._rec_simulation_stop(rec_ctx):
            self.states_found.append(state)
            return

        for pred in list(self.cfg.model.get_predecessors(initial_node)):
            new_rec_ctx = RecursiveCtx(rec_ctx.current_depth + 1, state, rec_ctx.path + [pred])
            self._rec_simulate(target_node, new_rec_ctx)

    def _handle_no_found_state(self, rec_ctx: RecursiveCtx) -> None:
        if rec_ctx.backup_state:
            self.states_found.append(rec_ctx.backup_state)

    def _set_state_to_vars(self, state: angr.SimState) -> None:
        for var in self.variables:
            var.set_ref_states([state])

    def _rec_simulation_stop(self, rec_ctx: RecursiveCtx) -> bool:
        happy_stop =  all(var.is_concrete() for var in self.variables)
        forced_stop = rec_ctx.current_depth >= self.max_depth
        return happy_stop or forced_stop

    def _simulate_slice(
        self,
        start: Address,
        target_node: CFGNode,
        pred: list[CFGNode],
    ) -> angr.SimState | None:

        initial = self._initialize_state(start)
        simgr = self.project.factory.simulation_manager(initial)
        state_found = self._get_finding(simgr, self._node_addr(target_node))

        while simgr.active and not state_found:
            self._remove_states(simgr.active, pred)
            simgr.step() # type: ignore [no-untyped-call]
            state_found = self._get_finding(simgr, self._node_addr(target_node))

        return state_found

    def _get_finding(self, simgr: angr.SimulationManager, target: Address) -> angr.SimState | None:
        return next((state for state in simgr.active if state.addr == target), None)

    def _remove_states(self, active_states: list[angr.SimState], pred: list[CFGNode]) -> None:
        for state in active_states:
            if self._remove_condition(state, pred):
                active_states.remove(state)

    def _remove_condition(self, state: angr.SimState, pred: list[CFGNode]) -> bool:
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
        project: angr.Project,
        init_addr: Address,
        stop: Callable[[list[angr.SimState]], bool],
        **inspect_kwargs: Any
    ) -> None:

        super().__init__(project)
        self.init_addr = init_addr
        self.stop = stop
        self.inspect_kwargs = inspect_kwargs

    @override
    def simulate(self) -> list[angr.SimState]:
        initial = self._initialize_state(self.init_addr)
        simulation = self.project.factory.simulation_manager(initial)
        initial.inspect.b(**self.inspect_kwargs) # type: ignore [no-untyped-call]

        while simulation.active and not self.stop(simulation.active):
            simulation.step() # type: ignore [no-untyped-call]

        return simulation.active


class BackwardSliceSimulation(Simulator):
    """
    TODO: This only works when init_addr and target are the begggining of a block
    """
    def __init__(self, project: angr.Project, init_addr: Address, target: Address) -> None:
        super().__init__(project)
        self.init_addr = init_addr
        self.target = target

    def _annotated_cfg(
        self,
        cfg: angr.analyses.CFGEmulated,
        target_node: CFGNode
    ) -> angr.analyses.CFGEmulated:

        bs = self.project.analyses.BackwardSlice(
            cfg, None, None,
            targets=[(target_node, -1)],
            control_flow_slice=True
        )
        acfg: angr.analyses.CFGEmulated = bs.annotated_cfg() # type: ignore [no-untyped-call]
        return acfg

    def _target_node(self, cfg: angr.analyses.CFGEmulated) -> CFGNode:
        cfg_nodes: list[CFGNode] = cfg.nodes()
        for node in cfg_nodes:
            if node.size and node.addr <= self.target < node.addr + node.size:
                return node
        raise ValueError("Target node was not found")

    @override
    def simulate(self) -> list[angr.SimState]:
        initial = self._initialize_state(self.init_addr, {angr.options.LAZY_SOLVES})
        simgr = self.project.factory.simgr(initial) # type: ignore [no-untyped-call]

        cfg = self.project.analyses.CFGEmulated(keep_state=True, starts=[self.init_addr])
        target_node = self._target_node(cfg)
        slicecutor = angr.exploration_techniques.Slicecutor(self._annotated_cfg(cfg, target_node))
        simgr.use_technique(slicecutor)

        found_states: list[angr.SimState] = []
        initial.inspect.b( # type: ignore [no-untyped-call]
            'instruction', when=angr.BP_AFTER, instruction=target_node.addr,
            action=lambda state: found_states.append(deepcopy(state))
        )

        while simgr.active:
            simgr.step()

        return found_states
