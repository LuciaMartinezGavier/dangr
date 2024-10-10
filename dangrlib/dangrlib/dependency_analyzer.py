from typing import Final
from itertools import product
from networkx import DiGraph
from networkx.algorithms import has_path
from multimethod import multimethod
import angr

from dangrlib.dangr_types import Address
from dangrlib.variables import Variable, Literal, Register, Memory, Deref, VariableFactory
from dangrlib.simulator import ForwardSimulation

class DependencyAnalyzer:
    """
    A class for analyzing dependencies between variables in a binary program using a
    Dependency Dependency Graph (DDG).
    """
    CALL_DEPTH_DEFAULT: Final = 10

    def __init__(self, project: angr.Project, variable_factory: VariableFactory, call_depth: int | None = None):
        self.project = project
        self.ddg: DiGraph | None = None
        self.call_depth = call_depth or self.CALL_DEPTH_DEFAULT
        self.variable_factory = variable_factory

    def create_dependency_graph(self, start_address: Address) -> None:
        """
        Create a Dependency Dependency Graph (DDG) starting from the given address.

        Args:
            start_address (Address): The starting address for the DDG creation.
        """
        cfg = self.project.analyses.CFGEmulated(
            keep_state=True,
            starts=[start_address],
            call_depth=self.call_depth,
            state_add_options=angr.sim_options.refs | {angr.sim_options.NO_CROSS_INSN_OPT},
        )

        self.ddg = self.project.analyses.DDG(cfg=cfg, start=start_address)

    def _instr_dep(self, source: Address, target: Address) -> bool:
        """
        Checks if there exists a path in the data dependency graph
        """
        return any(
            has_path(self.ddg.graph, src_node, trg_node)
            for src_node, trg_node in product(
                self._find_reference_nodes(source),
                self._find_reference_nodes(target)
            )
        )

    def _find_reference_nodes(self, addr: Address) -> list[angr.code_location.CodeLocation]:
        return [node for node in self.ddg.graph.nodes() if node.ins_addr == addr]

    def check_dependency(self, source: Variable, target: Variable, func_addr: Address) -> bool:
        """
        Check if `source` affects the value of `target`

        Args:
            source (Variable): The source variable to check for dependencies.
            target (Variable): The target variable to check for dependencies.

        Returns:
            bool: True if a dependency path is found from source to target, False otherwise.

        Raises:
            ValueError: If the dependency graph has not been created.
        """
        if not self.ddg:
            raise ValueError("Dependency graph is None. Call create_dependency_graph() first.")
        return self._instr_dep(source.ref_addr, target.ref_addr) and \
               self._variable_dep(source, target, func_addr)

    @multimethod
    def _variable_dep(self, source: Variable, target: Literal, func_addr: Address) -> bool:
        return False

    @multimethod
    def _variable_dep(self, source: Literal, target: Memory | Register | Deref, func_addr: Address) -> bool:
        # Literal might affect Memory or Register and that depends on the ddg only
        return True

    def _simulate_to_get_deps(self, target: Variable, func_addr) -> list[angr.SimState]:
        simulator = ForwardSimulation(self.project, func_addr, target=target.ref_addr)
        states = simulator.simulate()
        target.set_ref_state(states)
        return target.dependencies(self.variable_factory)

    @multimethod
    def _variable_dep(self, source: Deref, target: Register | Memory | Deref, func_addr: Address) -> bool:
        # Check is source depends on *any* Memory
        return any(isinstance(var, Memory) for var in self._simulate_to_get_deps(target, func_addr))

    @multimethod
    def _variable_dep(self, source: Memory, target: Register | Memory | Deref, func_addr: Address) -> bool:
        # Check if register is part of target
        return source in self._simulate_to_get_deps(target, func_addr)


    @multimethod
    def _variable_dep(self, source: Register, target: Register | Memory | Deref, func_addr: Address) -> bool:
        # Check if register is part of target
        reg_deps = [dep.normalized_name() for dep in self._simulate_to_get_deps(target, func_addr) if isinstance(dep, Register)]
        return source.normalized_name() in reg_deps
