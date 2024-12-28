from collections import namedtuple
from copy import deepcopy
from typing import Final
import angr

from dangr_rt.variables import Variable
from dangr_rt.simulator import ForwardSimulation, ConcreteState, initialize_state
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
    DEFAULT_NUM_FINDS: Final[int] = 64

    def __init__(
        self,
        project: angr.Project,
        num_finds: int | None = None,
        timeout: int | None = None
    ) -> None:
        self.project = project
        self.simulator = ForwardSimulation(project, num_finds or self.DEFAULT_NUM_FINDS, timeout)
        self.variables: list[Variable] = []
        self.constraints: list[Expression[AngrBool]] = []

    def add_variables(self, variables: list[Variable]) -> None:
        self.variables.extend(variables)

    def add_constraints(self, constraints: list[Expression[AngrBool]]) -> None:
        self.constraints.extend(constraints)

    def remove_constraints(self) -> None:
        self.constraints = []

    def simulate(
        self,
        target: Address,
        init_addr: Address,
        initial_values_list: list[ConcreteState] | None = None
    ) -> list[list[angr.SimState]]:
        """
        Symbolic execute adding the constraints until reaching que target

        TODO: explain what does list[list[angr.SimState]] mean
        """
        checkpoints = self._create_checkpoints(init_addr, target)
        found_states = []

        if not initial_values_list:
            blank_state = initialize_state(self.project, init_addr)
            found_states.append(self._rec_simulate(blank_state, 0, checkpoints))
        else:
            for initial_values in initial_values_list:
                init_state = initialize_state(self.project, init_addr, initial_values)
                found_states.append(self._rec_simulate(init_state, 0, checkpoints))

        return found_states

    def _rec_simulate(self, active_state, checkpoint_idx: int, checkpoints: Checkpoints):

        if checkpoint_idx >= len(checkpoints.items()):
            return [active_state]

        target, action_elem = list(checkpoints.sorted().items())[checkpoint_idx]
        next_starts = self.simulator.simulate(active_state, target)
        found_states = []

        for next_start in next_starts:
            self._set_state_to_vars(action_elem.variables, next_start)
            self._add_constraints_to_state(action_elem.constraints, next_start)

            if not next_start.solver.satisfiable():
                continue

            found_states.extend(
                self._rec_simulate(next_start, checkpoint_idx+1, deepcopy(checkpoints))
            )

        return found_states

    def _set_state_to_vars(self, variables: list[Variable], state: angr.SimState) -> None:
        for var in variables:
            var.set_ref_state(state)

    def _add_constraints_to_state(
        self,
        constraints: list[Expression[AngrBool]],
        state: angr.SimState
    ) -> None:
        for constraint in constraints:
            state.solver.add(constraint.get_expr())

    def _create_checkpoints(self, init_addr: Address, target: Address) -> Checkpoints:
        checkpoints = Checkpoints()
        self._create_var_checkpoints(checkpoints)
        self._create_constr_checkpoints(checkpoints, init_addr)
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
