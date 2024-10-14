from typing import Final,ItemsView
from collections import namedtuple
from functools import wraps
import angr
from itertools import product

from dangrlib.jasm_findings import StructuralFinding
from dangrlib.dangr_types import Address, Path, BYTE_SIZE
from dangrlib.variables import Variable
from dangrlib.variable_factory import VariableFactory
from dangrlib.expression import ExpressionNode
from dangrlib.simulator import Simulator, StepSimulation, ConcreteState
from dangrlib.arguments_analyzer import ArgumentsAnalyzer
from dangrlib.dependency_analyzer import DependencyAnalyzer

class DangrAnalysis:
    """
    Class that provides all the interface necesary for the analysis
    """

    def __init__(self, binary_path: Path, max_depth: int = 10) -> None:
        """
        Here we set all the attributes that are independent from the structural finding
        """
        # general config
        self.project: Final = angr.Project(binary_path, load_options={"auto_load_libs": False})
        self.cfg: Final = self.project.analyses.CFGFast()

        # helper modules init
        self.variable_factory = VariableFactory(self.project)
        self.dependency_analyzer = DependencyAnalyzer(self.project, self.variable_factory)
        self.simulator: Simulator | None = None
        self.arguments_analyzer = ArgumentsAnalyzer(self.project, self.cfg, max_depth)

        # structural finding related
        self.struct_f: StructuralFinding | None = None
        self.current_function: Address | None = None

        # simulation related
        self.constraints: list[ExpressionNode]  = []
        self.variables: list[Variable] = []

    @staticmethod
    def struct_finding_is_set(method):
        """
        Decorator that checks if self.simulator, self.struct_f, and self.current_function
        are not None. Raises ValueError if any of them is None, indicating that
        set_finding should be called first.
        """
        @wraps(method)
        def wrapper(self, *args, **kwargs):
            if self.simulator is None or self.struct_f is None or self.current_function is None:
                raise ValueError("Analysis not properly initialized. Call `set_finding()` first.")
            return method(self, *args, **kwargs)

        return wrapper


    def add_variables(self, variables: list[Variable]) -> None:
        self.variables.extend(variables)

    def set_finding(self, struct_f: StructuralFinding) -> None:
        """
        Sets the structural finding and updates the current function.

        Args:
            struct_f (StructuralFinding): The new structural finding to set.
        """
        self.struct_f = struct_f

        # Restart analysis
        self.current_function = self._find_function()
        self.simulator = StepSimulation(project=self.project, init_addr=self.current_function)
        self.dependency_analyzer.create_dependency_graph(self.current_function)
        self.constraints = []
        self.variables = []

    def get_variable_factory(self) -> VariableFactory:
        return self.variable_factory

    def _find_function(self) -> Address:
        """
        Gets the address of the function that contains the structural pattern matched.

        Raises:
            ValueError: If no single function contains the matched address range, 
            typically caused by the jasm pattern spanning multiple functions.
        """
        if self.struct_f is None:
            raise ValueError('Structural finding not set')

        for fn in self.cfg.kb.functions.values():
            if (fn.addr <= self.struct_f.start) and (self.struct_f.end <= fn.addr + fn.size):
                return Address(fn.addr)

        raise ValueError(f'Function not found for target address {hex(self.struct_f.start)}')


    @struct_finding_is_set
    def get_fn_args(self) -> list[Variable]:
        return self.arguments_analyzer.get_fn_args(self.current_function) # type: ignore [arg-type]

    @struct_finding_is_set
    def concretize_fn_args(self) -> list[ConcreteState]:
        """
        Returns a list with the concrete possible values of the arguments used
        in the function being analyzed

        Returns:
            list[ConcreteState]: all the possible combinations of the arguments values
        """
        return self.arguments_analyzer.solve_arguments(self.current_function, self.get_fn_args()) # type: ignore [arg-type]

    @struct_finding_is_set
    def simulate(
        self,
        target: Address,
        init_states: list[ConcreteState] | None = None
    ) -> list[angr.SimState]:
        """
        Symbolic execute the current function until the target is found
        """
        checkpoints = self._create_checkpoints(target)
        for addr, action_elem in checkpoints.items():

            found_states: list[angr.SimState] = []
            self.simulator.set_step_target(target=addr) # type: ignore [union-attr]

            if not init_states:
                found_states.extend(self.simulator.simulate()) # type: ignore [union-attr]
            else:
                for init_state in init_states:
                    self.simulator.set_initial_values(init_state) # type: ignore [union-attr]
                    found_states.extend(self.simulator.simulate()) # type: ignore [union-attr]
            self._set_states_to_vars(action_elem.variables, found_states)
            self._add_constraints_to_states(action_elem.constraints, found_states)

        return found_states

    def _set_states_to_vars(self, variables: list[Variable], states: list[angr.SimState]) -> None:
        for var in variables:
            var.set_ref_states(states)

    def _add_constraints_to_states(
        self,
        constraints: list[ExpressionNode],
        states: list[angr.SimState]
    ) -> None:

        for constraint in constraints:
            for expr in constraint.create_expressions():
                for state in states:
                    state.add_constraints(expr)


    def _create_checkpoints(self, target: Address) -> 'Checkpoints':
        checkpoints = Checkpoints()

        for variable in self.variables:
            checkpoints.add_variable(variable.ref_addr, variable)

        for constraint in self.constraints:
            checkpoints.add_constraint(constraint.expression_address(), constraint)

        if checkpoints.last_address() is None or checkpoints.last_address() < target: # type: ignore [operator]
            checkpoints.add_address(target)

        return checkpoints.sorted()

    def add_constraint(self, constraint: ExpressionNode) -> None:
        """
        Adds a constraints to the analysis
        """
        self.constraints.append(constraint)


    def satisfiable(self, states: list[angr.SimState]) -> bool:
        """
        Returns True if all the constraints can be satisfied at the same time
        in any of the states given.
        """
        return any(state.solver.satisfiable() for state in states)

    def depends(self, source: Variable, target: Variable) -> bool:
        """
        Calculates dependencies of a given variable
        """
        return self.dependency_analyzer.check_dependency(source, target)

    def upper_bounded(
        self, expr_tree: ExpressionNode,
        states: list[angr.SimState], offset: int = 0
    ) -> bool:
        return all(
            state.solver.max(expr) < 2**(expr_tree.size() * BYTE_SIZE) - offset
            for expr, state in product(expr_tree.create_expressions(), states)
        )

CheckpointGroup = namedtuple('CheckpointGroup', ['variables', 'constraints'])

class Checkpoints(dict[Address, CheckpointGroup]):

    @staticmethod
    def ensure_address(func):
        """
        Initialize lists
        """
        @wraps(func)
        def wrapper(self, addr, *args, **kwargs):
            if addr not in self:
                self.add_address(addr)
            return func(self, addr, *args, **kwargs)
        return wrapper

    @ensure_address
    def add_variable(self, address: Address, variable: Variable) -> None:
        self[address].variables.append(variable)

    @ensure_address
    def add_constraint(self, address: Address, constraint: ExpressionNode) -> None:
        self[address].constraints.append(constraint)

    def add_address(self, address: Address) -> None:
        self[address] = CheckpointGroup([], [])

    def sorted(self) -> 'Checkpoints':
        """
        Return a new Checkpoints object with items sorted by the dictionary keys.
        """
        sorted_checkpoints = Checkpoints(sorted(self.items()))
        return sorted_checkpoints


    def last_address(self) -> Address | None:
        if not self:
            return None

        sorted_checkpoints = self.sorted()
        last_key = next(reversed(sorted_checkpoints), None)
        return last_key
