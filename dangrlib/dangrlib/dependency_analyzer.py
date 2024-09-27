import angr
from networkx import DiGraph
from networkx.algorithms import has_path
from itertools import product
from dangr_types import Address
from variables import Variable, Literal, Register, Memory, Deref
from multimethod import multimethod
from simulation_manager import Simulator

class DependencyAnalyzer:
    """
    A class for analyzing dependencies between variables in a binary program using a
    Dependency Dependency Graph (DDG).
    """
    def __init__(self, project: angr.Project):
        self.project = project
        self.ddg: DiGraph | None = None

    def create_dependency_graph(self, start_address: Address) -> None:
        """
        Create a Dependency Dependency Graph (DDG) starting from the given address.

        Args:
            start_address (Address): The starting address for the DDG creation.
        """
        cfg = self.project.analyses.CFGEmulated(
            keep_state=True,
            starts=[start_address],
            call_depth=10, # FIXME: poner como argumento
            state_add_options=angr.sim_options.refs
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

    def check_dependency(self, source: Variable, target: Variable, simulator: Simulator) -> bool:
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
        return self._instr_dep(source.reference_address, target.reference_address) and \
               self._variable_dep(source, target, simulator)

    @multimethod
    def _variable_dep(self, source: Variable, target: Literal, simulator: Simulator) -> bool:
        return False

    @multimethod
    def _variable_dep(self, source: Literal, target: Memory | Register | Deref, simulator: Simulator) -> bool:
        # Literal might affect Memory or Register and that depends on the ddg only
        return True

    def _simulate_to_get_deps(self, target: Variable, simulator: Simulator) -> list[angr.SimState]:
        states = simulator.simulate(target.reference_address)
        target.set_ref_state(states)
        return target.dependencies()

    @multimethod
    def _variable_dep(self, source: Deref, target: Register | Memory | Deref, simulator: Simulator) -> bool:
        # Check is source depends on *any* 
        return any(isinstance(var, Memory) for var in self._simulate_to_get_deps(target, simulator))

    @multimethod
    def _variable_dep(self, source: Memory, target: Register | Memory | Deref, simulator: Simulator) -> bool:
        # Check if register is part of target
        return source in self._simulate_to_get_deps(target, simulator)

    @multimethod
    def _variable_dep(self, source: Register, target: Register | Memory | Deref, simulator: Simulator) -> bool:
        # Check if register is part of target
        reg_deps = [dep.name for dep in self._simulate_to_get_deps(target, simulator) if isinstance(dep, Register)]
        return source.name in reg_deps
