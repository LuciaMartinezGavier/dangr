from abc import ABC, abstractmethod
from typing import Final, Any, Sequence
import angr
from dangr_rt.jasm_findings import JasmAPI, JasmMatch, VariableMatch
from dangr_rt.dangr_types import Address, Path, AngrBool, Argument
from dangr_rt.variables import Variable, Register
from dangr_rt.variable_factory import VariableFactory
from dangr_rt.expression import Expression
from dangr_rt.simulator import ConcreteState
from dangr_rt.arguments_analyzer import ArgumentsAnalyzer
from dangr_rt.dependency_analyzer import DependencyAnalyzer
from dangr_rt.dangr_simulation import DangrSimulation


class DangrAnalysis(ABC): # pylint: disable=too-many-instance-attributes
    """
    Class that provides all the interface necesary for the analysis
    """

    def __init__(self, binary_path: Path, config: dict[str, Any]) -> None:
        """
        Here we set all the attributes that are independent from the structural finding
        """
        # general config
        self.binary_path = binary_path
        self.config = config
        self._project: Final = angr.Project(binary_path, load_options={"auto_load_libs": False})
        self._cfg: Final = self._project.analyses.CFGFast()
        self._current_function: Address | None = None

        # helper modules init
        self._simulator: DangrSimulation | None = None
        self._variable_factory = VariableFactory(self._project)
        self._dependency_analyzer = DependencyAnalyzer(
            self._project,
            call_depth=self.config.get('cfg_call_depth', None),
            max_steps=self.config.get('cfg_max_steps', None),
            resolve_indirect_jumps=self.config.get('cfg_resolve_indirect_jumps', None)
        )
        self._arguments_analyzer = ArgumentsAnalyzer(
            self._project,
            self._cfg,
            self.config.get('max_depth', None)
        )

    def _jasm_match_set(self) -> None:
        """
        Checks if self.simulator, self.jasm_match, and self.current_function
        are not None. Raises ValueError if any of them is None, indicating that
        set_finding should be called first.
        """
        if self._simulator is None or self._current_function is None:
            raise ValueError("Analysis not properly initialized. Call `set_finding()` first.")

    def _add_variables(self, variables: list[Variable]) -> None:
        self._jasm_match_set()
        self._simulator.add_variables(variables) # type: ignore [union-attr]

    def _init_match_analysis(self, jasm_match: JasmMatch) -> None:
        """
        Sets the structural finding and updates the current function.

        Args:
            jasm_match (JasmMatch): The new structural finding to set.
        """
        # self._jasm_match = jasm_match

        # Restart analysis
        self._current_function = self._find_function(jasm_match)
        self._simulator = DangrSimulation(
            project=self._project,
            num_finds=self.config.get('num_finds', None),
            timeout=self.config.get('timeout', None)
        )
        self._dependency_analyzer.create_dependency_graph(self._current_function)

    def _create_var_from_capture(self, var: VariableMatch) -> Variable:
        """
        Creates a Variable from the JASM's match info.
        """
        return self._variable_factory.create_from_capture(var)

    def _create_var_from_argument(self, argument: Argument) -> Variable:
        """
        Creates a Variable from a function argument based on its index.
        """
        return self._variable_factory.create_from_argument(argument)

    def _create_deref(self, base: Variable, idx: int = 0) -> Variable:
        """
        Creates a dereference of a base register, optionally it is possible to add an index.
        """
        return self._variable_factory.create_deref(base, idx, self.config.get('reverse', None))

    def _find_function(self, jasm_match: JasmMatch) -> Address:
        """
        Gets the address of the function that contains the structural pattern matched.

        Raises:
            ValueError: If no single function contains the matched address range, 
            typically caused by the jasm pattern spanning multiple functions.
        """
        if jasm_match is None:
            raise ValueError('Structural finding not set')

        for fn in self._cfg.kb.functions.values():
            if self._finding_in_func(jasm_match, fn):
                return Address(fn.addr)

        raise ValueError('Function not found for target address: '
        f'start at {hex(jasm_match.start)}, end at {hex(jasm_match.end)}')

    def _finding_in_func(
        self, jasm_match: JasmMatch,
        fn: angr.knowledge_plugins.functions.function.Function
    ) -> bool:
        if jasm_match is None:
            raise ValueError('Structural finding not set')

        return bool(
            (fn.addr <= jasm_match.start) and\
            (jasm_match.end <= fn.addr + fn.size))

    def _get_fn_args(self) -> Sequence[Register]:
        self._jasm_match_set()
        return self._arguments_analyzer.get_fn_args(self._current_function) # type: ignore [arg-type]

    def _concretize_fn_args(self) -> list[ConcreteState]:
        """
        Returns a list with the concrete possible values of the arguments used
        in the function being analyzed

        Returns:
            list[ConcreteState]: all the possible combinations of the arguments values
        """
        self._jasm_match_set()

        return self._arguments_analyzer.solve_arguments(
            # already checked in _jasm_match_set() ↓
            self._current_function, # type: ignore [arg-type]
            self._get_fn_args()
        )

    def _simulate(
        self,
        target: Address,
        init_states: list[ConcreteState] | None = None
    ) -> list[list[angr.SimState]]:

        self._jasm_match_set()
        return self._simulator.simulate( # type: ignore [union-attr]
            target, self._current_function, init_states # type: ignore [arg-type]
        )

    def _add_constraint(self, constraint: Expression[AngrBool]) -> None:
        """
        Adds a constraints to the analysis
        """
        self._jasm_match_set()
        self._simulator.add_constraints([constraint]) # type: ignore [union-attr]

    def _remove_constraints(self) -> None:
        """
        Remove all constraints from execution
        """
        self._jasm_match_set()
        self._simulator.remove_constraints() # type: ignore [union-attr]

    def _satisfiable(self, states: list[angr.SimState]) -> bool:
        """
        Returns True if all the constraints can be satisfied at the same time
        in any of the states given.
        """
        for state in states:
            state.solver.reload_solver() # type: ignore [no-untyped-call]
            if state.solver.satisfiable():
                return True
        return False

    def _depends(self, source: Variable, target: Variable) -> bool:
        """
        Calculates dependencies of a given variable
        """
        return self._dependency_analyzer.check_dependency(source, target)

    def analyze(self, jasm_pattern) -> str | None:
        """
        Template method that performs the analysis given a jasm pattern 
        """
        jasm_matches = JasmAPI().run(self.binary_path, jasm_pattern)

        for jasm_match in jasm_matches:
            self._init_match_analysis(jasm_match)
            match_analysis_res = self._analyze_asm_match(jasm_match)

            if match_analysis_res is not None:
                return match_analysis_res

    @abstractmethod
    def _analyze_asm_match(self, jasm_match: JasmMatch) -> str | None:
        pass
