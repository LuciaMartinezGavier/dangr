from typing import Final, Callable, Any
from dataclasses import dataclass
import angr

from dangr_rt.variables import Variable
from dangr_rt.dangr_types import Address, CFGNode
ConcreteState = dict['Variable', int]

def initialize_state(
    project: angr.Project,
    start: Address,
    initial_values: ConcreteState | None = None,
    add_options: set[str] | None = None
) -> angr.SimState:
    """"
    Sets the initial values in a new state and returns it
    """
    state: angr.SimState = project.factory.blank_state( # type: ignore [no-untyped-call]
        addr=start,
        add_options=add_options
    )

    if initial_values is None:
        return state

    for var, value in initial_values.items():
        var.set_ref_state(state)
        var.set_value(value)

    return state


class ForwardSimulation:
    """
    Simulate until reaching a target
    """
    def __init__(
        self,
        project: angr.Project,
        num_finds: int,
        timeout: int | None = None
    ) -> None:
        self.project = project
        self.timeout = timeout
        self.num_finds = num_finds

    def simulate(
        self,
        initial_state: angr.SimState,
        target: Address
    ) -> list[angr.SimState]:
        """
        Simulate from a given state until reaching a target address
        """
        simulation = self.project.factory.simulation_manager(initial_state)
        simulation.use_technique(
            angr.exploration_techniques.Timeout(self.timeout)
        ) # type: ignore [no-untyped-call]
        simulation.explore(find=target, num_find=self.num_finds) # type: ignore [no-untyped-call]

        return simulation.found


class HookSimulation:
    """
    Simulate until reaching a target
    """
    def __init__(
        self,
        project: angr.Project,
        init_addr: Address,
        stop: Callable[[list[angr.SimState]], bool],
        initial_values: None | ConcreteState = None,
        **inspect_kwargs: Any
    ) -> None:

        self.project = project
        self.init_addr = init_addr
        self.stop = stop
        self.initial_values = initial_values
        self.inspect_kwargs = inspect_kwargs

    def simulate(self) -> list[angr.SimState]:
        initial = initialize_state(self.project, self.init_addr, self.initial_values)
        simulation = self.project.factory.simulation_manager(initial)
        initial.inspect.b(**self.inspect_kwargs) # type: ignore [no-untyped-call]

        while simulation.active and not self.stop(simulation.active):
            simulation.step() # type: ignore [no-untyped-call]

        return simulation.active


@dataclass
class RecursiveCtx:
    current_depth: int
    backup_state: angr.SimState | None
    path: list[CFGNode]


class BackwardSimulation:
    """
    Simualte backwards until variables are concrete
    """
    _EXTERNAL_ADDR_SPACE_BASE: Final = 0x50_0000
    DEFAULT_MAX_DEPTH: Final[int] = 1

    def __init__( # pylint: disable=too-many-arguments
        self, project: angr.Project, *, target: Address,
        cfg: angr.analyses.CFGFast, variables: list[Variable],
        max_depth: int | None = None
    ) -> None:

        self.project = project
        self.target = target
        self.cfg = cfg
        self.variables = variables
        self.states_found: list[angr.SimState] = []
        self.max_depth: Final = max_depth or self.DEFAULT_MAX_DEPTH

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
            var.set_ref_state(state)

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

        initial = initialize_state(self.project, start)
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
        is_external_block =  state.addr >= self._EXTERNAL_ADDR_SPACE_BASE
        is_in_slice = state.addr in [p.addr for p in pred]
        return not is_in_slice or is_external_block or already_visited
