from typing import Final, Any, Sequence
import angr
from dangr_rt.jasm_findings import JasmMatch, VariableMatch
from dangr_rt.dangr_types import Address, Path, AngrBool, Argument
from dangr_rt.variables import Variable, Register
from dangr_rt.variable_factory import VariableFactory
from dangr_rt.expression import Expression
from dangr_rt.simulator import ConcreteState
from dangr_rt.arguments_analyzer import ArgumentsAnalyzer
from dangr_rt.dependency_analyzer import DependencyAnalyzer
from dangr_rt.dangr_simulation import DangrSimulation

class DangrAnalysis: # pylint: disable=too-many-instance-attributes
    """
    Class that provides all the interface necesary for the analysis
    """

    def __init__(self, binary_path: Path, config: dict[str, Any]) -> None:
        """
        Here we set all the attributes that are independent from the structural finding
        """
        # general config
        self.project: Final = angr.Project(binary_path, load_options={"auto_load_libs": False})
        self.cfg: Final = self.project.analyses.CFGFast()
        self.config = config
        self.current_function: Address | None = None
        self.jasm_match: JasmMatch | None = None

        # helper modules init
        self.simulator: DangrSimulation | None = None
        self.variable_factory = VariableFactory(self.project)
        self.dependency_analyzer = DependencyAnalyzer(
            self.project,
            call_depth=self.config.get('cfg_call_depth', None),
            max_steps=self.config.get('cfg_max_steps', None),
            resolve_indirect_jumps=self.config.get('cfg_resolve_indirect_jumps', None)
        )
        self.arguments_analyzer = ArgumentsAnalyzer(
            self.project,
            self.cfg,
            self.config.get('max_depth', None)
        )

    def _jasm_match_set(self) -> None:
        """
        Checks if self.simulator, self.jasm_match, and self.current_function
        are not None. Raises ValueError if any of them is None, indicating that
        set_finding should be called first.
        """
        if self.simulator is None or self.jasm_match is None or self.current_function is None:
            raise ValueError("Analysis not properly initialized. Call `set_finding()` first.")

    def add_variables(self, variables: list[Variable]) -> None:
        self._jasm_match_set()
        self.simulator.add_variables(variables) # type: ignore [union-attr]

    def set_finding(self, jasm_match: JasmMatch) -> None:
        """
        Sets the structural finding and updates the current function.

        Args:
            jasm_match (JasmMatch): The new structural finding to set.
        """
        self.jasm_match = jasm_match

        # Restart analysis
        self.current_function = self._find_function()
        self.simulator = DangrSimulation(
            project=self.project,
            num_finds=self.config.get('num_finds', None),
            timeout=self.config.get('timeout', None)
        )
        self.dependency_analyzer.create_dependency_graph(self.current_function)

    def create_var_from_capture(self, var: VariableMatch) -> Variable:
        """
        Creates a Variable from the JASM's match info.
        """
        return self.variable_factory.create_from_capture(var)

    def create_var_from_argument(self, argument: Argument) -> Variable:
        """
        Creates a Variable from a function argument based on its index.
        """
        return self.variable_factory.create_from_argument(argument)

    def create_deref(self, base: Variable, idx: int = 0) -> Variable:
        return self.variable_factory.create_deref(base, idx, self.config.get('reverse', None))

    def _find_function(self) -> Address:
        """
        Gets the address of the function that contains the structural pattern matched.

        Raises:
            ValueError: If no single function contains the matched address range, 
            typically caused by the jasm pattern spanning multiple functions.
        """
        if self.jasm_match is None:
            raise ValueError('Structural finding not set')

        for fn in self.cfg.kb.functions.values():
            if self._finding_in_func(fn):
                return Address(fn.addr)

        raise ValueError('Function not found for target address: '
        f'start at {hex(self.jasm_match.start)}, end at {hex(self.jasm_match.end)}')

    def _finding_in_func(self, fn: angr.knowledge_plugins.functions.function.Function) -> bool:
        if self.jasm_match is None:
            raise ValueError('Structural finding not set')

        return bool(
            (fn.addr <= self.jasm_match.start) and\
            (self.jasm_match.end <= fn.addr + fn.size))

    def get_fn_args(self) -> Sequence[Register]:
        self._jasm_match_set()
        return self.arguments_analyzer.get_fn_args(self.current_function) # type: ignore [arg-type]

    def concretize_fn_args(self) -> list[ConcreteState]:
        """
        Returns a list with the concrete possible values of the arguments used
        in the function being analyzed

        Returns:
            list[ConcreteState]: all the possible combinations of the arguments values
        """
        self._jasm_match_set()

        return self.arguments_analyzer.solve_arguments(
            # already checked in _jasm_match_set() ↓
            self.current_function, # type: ignore [arg-type]
            self.get_fn_args()
        )

    def simulate(
        self,
        target: Address,
        init_states: list[ConcreteState] | None = None
    ) -> list[angr.SimState]:
        self._jasm_match_set()
        return self.simulator.simulate( # type: ignore [union-attr]
            target, self.current_function, init_states # type: ignore [arg-type]
        )

    def add_constraint(self, constraint: Expression[AngrBool]) -> None:
        """
        Adds a constraints to the analysis
        """
        self._jasm_match_set()
        self.simulator.add_constraints([constraint]) # type: ignore [union-attr]

    def remove_constraints(self) -> None:
        self._jasm_match_set()
        self.simulator.remove_constraints() # type: ignore [union-attr]

    def satisfiable(self, states: list[angr.SimState]) -> bool:
        """
        Returns True if all the constraints can be satisfied at the same time
        in any of the states given.
        """
        for state in states:
            state.solver.reload_solver() # type: ignore [no-untyped-call]
            if state.solver.satisfiable():
                return True
        return False

    def depends(self, source: Variable, target: Variable) -> bool:
        """
        Calculates dependencies of a given variable
        """
        return self.dependency_analyzer.check_dependency(source, target)
