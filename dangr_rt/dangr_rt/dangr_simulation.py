from collections import namedtuple
import angr

from dangr_rt.variables import Variable
from dangr_rt.simulator import StepSimulation, ConcreteState
from dangr_rt.dangr_types import Address, AngrBool
from dangr_rt.expression import Expression

CheckpointGroup = namedtuple('CheckpointGroup', ['variables', 'constraints'])

class Checkpoints(dict[Address, CheckpointGroup]):

    def add_variable(self, address: Address, variable: Variable) -> None:
        if address not in self:
            self[address] = CheckpointGroup([], [])

        self[address].variables.append(variable)

    def add_constraint(self, address: Address, constraint: Expression[AngrBool]) -> None:
        if address not in self:
            self[address] = CheckpointGroup([], [])

        self[address].constraints.append(constraint)

    def sorted(self) -> 'Checkpoints':
        """
        Return a new Checkpoints object with items sorted by the dictionary keys.
        """
        sorted_checkpoints = Checkpoints(sorted(self.items()))
        return sorted_checkpoints

    def last_address(self) -> Address | None:
        if not self:
            return None

        last_key = next(reversed(self.sorted()), None)
        return last_key


class DangrSimulation:
    def __init__(
        self,
        project: angr.Project,
        init_addr: Address,
        timeout: int | None = None
    ) -> None:

        self.simulator = StepSimulation(project, init_addr, timeout)
        self.variables: list[Variable] = []
        self.constraints: list[Expression[AngrBool]] = []

    def add_variables(self, variables: list[Variable]) -> None:
        self.variables.extend(variables)

    def add_constraints(self, constraints: list[Expression[AngrBool]]) -> None:
        self.constraints.extend(constraints)

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
            self.simulator.set_step_target(target=addr)

            if not init_states:
                found_states.extend(self.simulator.simulate())
            else:
                for init_state in init_states:
                    self.simulator.set_initial_values(init_state)
                    found_states.extend(self.simulator.simulate())

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


    def _create_checkpoints(self, target: Address) -> Checkpoints:
        checkpoints = Checkpoints()
        self._create_var_checkpoints(checkpoints)
        self._create_constr_checkpoints(checkpoints, target)
        self._add_target_checkpoint(checkpoints, target)
        return checkpoints.sorted()

    def _create_var_checkpoints(self, checkpoints: Checkpoints) -> None:
        for variable in self.variables:
            checkpoints.add_variable(variable.ref_addr, variable)

    def _create_constr_checkpoints(self, checkpoints: Checkpoints, default_addr: Address) -> None:
        for constraint in self.constraints:
            checkpoints.add_constraint(constraint.ref_addr or default_addr, constraint)

    def _add_target_checkpoint(self, checkpoints: Checkpoints, target: Address) -> None:
        if checkpoints.last_address() is None or\
           checkpoints.last_address() < target: # type: ignore [operator]
            checkpoints[target] = CheckpointGroup([], [])
