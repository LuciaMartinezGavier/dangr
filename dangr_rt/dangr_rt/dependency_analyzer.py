from typing import Final
from itertools import product

from networkx import DiGraph # type: ignore [import-untyped]
from networkx.algorithms import has_path # type: ignore [import-untyped]

import angr

from dangr_rt.dangr_types import Address
from dangr_rt.variables import Variable
from dangr_rt.variable_factory import VariableFactory

class DependencyAnalyzer:
    """
    A class for analyzing dependencies between variables in a binary program using a
    Dependency Dependency Graph (DDG).
    """
    CALL_DEPTH_DEFAULT: Final = 10

    def __init__(
        self, project: angr.Project,
        variable_factory: VariableFactory,
        call_depth: int | None = None
    ):
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

    def _find_reference_nodes(self, addr: Address) -> list[angr.code_location.CodeLocation]:
        return [node for node in self.ddg.graph.nodes() if node.ins_addr == addr] # type: ignore [union-attr]

    def check_dependency(self, source: Variable, target: Variable) -> bool:
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

        return any(
            has_path(self.ddg.graph, src_node, trg_node)
            for src_node, trg_node in product(
                self._find_reference_nodes(source.ref_addr),
                self._find_reference_nodes(target.ref_addr)
            )
        )