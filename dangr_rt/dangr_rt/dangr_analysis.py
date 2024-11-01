from typing import Final, Any
from collections import namedtuple
import angr

from dangr_rt.jasm_findings import StructuralFinding
from dangr_rt.dangr_types import Address, Path, AngrBool
from dangr_rt.variables import Variable
from dangr_rt.variable_factory import VariableFactory
from dangr_rt.expression import Expression
from dangr_rt.simulator import Simulator, StepSimulation, ConcreteState
from dangr_rt.arguments_analyzer import ArgumentsAnalyzer
from dangr_rt.dependency_analyzer import DependencyAnalyzer

class DangrAnalysis:
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

        # helper modules init
        self.variable_factory = VariableFactory(self.project)
        self.dependency_analyzer = DependencyAnalyzer(self.project, self.variable_factory)
        self.simulator: Simulator | None = None
        self.arguments_analyzer = ArgumentsAnalyzer(self.project,
                                                    self.cfg,
                                                    self.config.get('max_depth', None))

        # structural finding related
        self.struct_f: StructuralFinding | None = None
        self.current_function: Address | None = None

        # simulation related
        self.constraints: list[Expression[AngrBool]]  = []
        self.variables: list[Variable] = []


    def _struct_finding_is_set(self) -> None:
        """
        Checks if self.simulator, self.struct_f, and self.current_function
        are not None. Raises ValueError if any of them is None, indicating that
        set_finding should be called first.
        """

        if self.simulator is None or self.struct_f is None or self.current_function is None:
            raise ValueError("Analysis not properly initialized. Call `set_finding()` first.")



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


    def get_fn_args(self) -> list[Variable]:
        self._struct_finding_is_set()
        return self.arguments_analyzer.get_fn_args(self.current_function) # type: ignore [arg-type]

    def concretize_fn_args(self) -> list[ConcreteState]:
        """
        Returns a list with the concrete possible values of the arguments used
        in the function being analyzed

        Returns:
            list[ConcreteState]: all the possible combinations of the arguments values
        """
        self._struct_finding_is_set()

        return self.arguments_analyzer.solve_arguments(
            # already checked in _struct_finding_is_set() ↓
            self.current_function, # type: ignore [arg-type]
            self.get_fn_args()
        )

    def simulate(
        self,
        target: Address,
        init_states: list[ConcreteState] | None = None
    ) -> list[angr.SimState]:
        """
        TODO: move this somewere else
        Symbolic execute the current function until the target is found
        """
        self._struct_finding_is_set()
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
        constraints: list[Expression[AngrBool]],
        states: list[angr.SimState]
    ) -> None:

        for constraint in constraints:
            for expr in constraint.get_expr():
                for state in states:
                    state.solver.add(expr)


    def _create_checkpoints(self, target: Address) -> 'Checkpoints':
        checkpoints = Checkpoints()

        for variable in self.variables:
            checkpoints.add_variable(variable.ref_addr, variable)

        for constraint in self.constraints:
            checkpoints.add_constraint(constraint.ref_addr or target, constraint)

        if checkpoints.last_address() is None or\
           checkpoints.last_address() < target: # type: ignore [operator]
            checkpoints.add_address(target)

        return checkpoints.sorted()

    def add_constraint(self, constraint: Expression[AngrBool]) -> None:
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

CheckpointGroup = namedtuple('CheckpointGroup', ['variables', 'constraints'])

class Checkpoints(dict[Address, CheckpointGroup]):

    def add_variable(self, address: Address, variable: Variable) -> None:
        if address not in self:
            self.add_address(address)

        self[address].variables.append(variable)

    def add_constraint(self, address: Address, constraint: Expression[AngrBool]) -> None:
        if address not in self:
            self.add_address(address)

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
