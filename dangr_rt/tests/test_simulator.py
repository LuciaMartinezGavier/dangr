
import subprocess
from dataclasses import dataclass
from math import prod
from typing import Final, Callable
import pytest
import angr
from tests.conftest import BinaryBasedTestCase, fullpath

from dangr_rt.variables import Register, Memory
from dangr_rt.dangr_types import Address
from dangr_rt.simulator import (
    ForwardSimulation, BackwardSimulation,
    HookSimulation, ConcreteState, initialize_state
)

SIMULATOR_DIR = 'simulator'



@dataclass(kw_only=True)
class ForwardSimulationTestCase(BinaryBasedTestCase):
    expected: Callable[list[angr.SimState], bool] | Callable[[list[angr.SimState], int], bool]
    start: Address
    target: Address
    initial_values: Callable[angr.Project, ConcreteState] | None = None
    files_directory: str = SIMULATOR_DIR

FOO: Final = 539
BAR: Final = 324
MEM: Final = 0xc0ca_c01a
ARR: Final = [3,6,2,8,5]

def array_to_hex(arr):
    hex_string = "0x"
    for num in arr:
        hex_string += f"00_00_00_{num:02x}_"

    return int(hex_string.rstrip('_'), 16)


FORWARD_SIMULATOR_TEST_CASES: Final = [
    ForwardSimulationTestCase(
        asm_filename='forward.s',
        start=0x40_00d4,
        target=0x40_0182,
        expected=lambda sts:\
            len(sts) == 1 and\
            sts[0].regs.rax.concrete and\
            sts[0].memory.load(MEM, 4).concrete and\
            sts[0].solver.eval(sts[0].regs.rax) == FOO + BAR and\
            sts[0].solver.eval(sts[0].memory.load(MEM, 4)) == 0,
        initial_values=lambda p: {
            Register(p, 'edi', 0x40_00dc): 1,
            Register(p, 'rsi', 0x40_00df): FOO,
            Register(p, 'rdx', 0x40_00e3): BAR,
            Register(p, 'rcx', 0x40_00e7): MEM
        }
    ),
    ForwardSimulationTestCase(
        asm_filename='forward.s',
        start=0x40_00d4,
        target=0x40_0182,
        expected=lambda sts:\
            len(sts) == 1 and\
            sts[0].regs.rax.concrete and\
            sts[0].memory.load(MEM, 4).concrete and\
            sts[0].solver.eval(sts[0].regs.rax) == 0 and\
            # NOTE: `reversed` because Intel uses little endian
            sts[0].solver.eval(sts[0].memory.load(MEM, 4).reversed) == 1,
        initial_values=lambda p: {
            Register(p, 'edi', 0x40_00dc): 4,
            Register(p, 'rsi', 0x40_00df): FOO,
            Register(p, 'rdx', 0x40_00e3): 0,
            Register(p, 'rcx', 0x40_00e7): MEM
        }
    ),
    ForwardSimulationTestCase(
        asm_filename='forward.s',
        start=0x40_00d4,
        target=0x40_0182,
        expected=lambda sts:
            len(sts) == 2 and\
            any(
                s.regs.rax.concrete and\
                s.solver.eval(s.regs.rax) == 0 and\
                s.memory.load(MEM, 4).concrete and\
                s.solver.eval(s.memory.load(MEM, 4).reversed) == 1
                for s  in sts
            ) and\
            any(
                not s.regs.rax.concrete and\
                s.memory.load(MEM, 4).concrete and\
                s.solver.eval(s.memory.load(MEM, 4).reversed) == 0
                for s  in sts
            ),
        initial_values=lambda p: {
            Register(p, 'edi', 0x40_00dc): 4,
            Register(p, 'rcx', 0x40_00e7): MEM,
        }
    )
]


@pytest.mark.parametrize("test_case", FORWARD_SIMULATOR_TEST_CASES, indirect=True)
def test_forward_simulation(test_case):
    p = angr.Project(test_case.binary, auto_load_libs=False)
    simulator = ForwardSimulation(p, num_finds=5)
    initial_state = initialize_state(p, test_case.start, test_case.initial_values(p))
    found = simulator.simulate(initial_state, test_case.target)
    assert test_case.expected(found)


def test_forward_simulation_with_steps():

    def step_validate(states, step):
        if not (len(states) == 1 and states[0].regs.edi.concrete):
            return False

        match step:
            case 0:
                expected = sum(ARR)
            case 1:
                expected = prod(ARR)
            case 2:
                expected = max(ARR)
            case 3:
                expected = sum([int(e/max(ARR)) for e in ARR])
            case _:
                return False

        return states[0].solver.eval(states[0].regs.edi) == expected


    asm_filepath = fullpath(SIMULATOR_DIR, "step.s")
    bin_filepath = asm_filepath.replace('.s', '.o')
    subprocess.run(["as", "--64", "-o", bin_filepath , asm_filepath], check=True)

    p = angr.Project(bin_filepath, auto_load_libs=False)

    simulator = ForwardSimulation(p, num_finds=5, timeout=3)

    initial_values = {
            Memory(p, MEM, len(ARR)*4, 0x40_000a): array_to_hex(ARR),
            Register(p, 'rdi', 40_0012): MEM,
            Register(p, 'esi', 40_0016): len(ARR)
    }

    step_targets = [0x40_0063, 0x40_00a1, 0x40_00f4, 0x40_017f]

    next_initial = initialize_state(p, 0x40_000a, initial_values)
    for step_idx, target in enumerate(step_targets):
        found_states = simulator.simulate(next_initial, target)
        assert step_validate(found_states, step_idx)
        next_initial = found_states[0]

@dataclass(kw_only=True)
class BackwardSimulationTestCase(BinaryBasedTestCase):
    simulator: Callable[angr.Project, BackwardSimulation]
    expected: Callable[list[angr.SimState], bool] | Callable[[list[angr.SimState], int], bool]
    files_directory: str = SIMULATOR_DIR

BACKWARD_SIMULATOR_TEST_CASES: Final = [
    BackwardSimulationTestCase(
        asm_filename='backward.s',
        simulator=lambda p: BackwardSimulation(
            p, target=0x40_0000, cfg=p.analyses.CFGFast(),
            variables=[Register(p, 'edi', 0x40_0004)], max_depth=5
        ),
        expected=lambda sts: len(sts) == 1 and\
                             sts[0].regs.edi.concrete and\
                             sts[0].solver.eval(sts[0].regs.edi) == 6,
    ),
    BackwardSimulationTestCase(
        asm_filename='backward.s',
        simulator=lambda p: BackwardSimulation(
            p, target=0x40_0000, cfg=p.analyses.CFGFast(),
            variables=[Register(p, 'edi', 0x40_0004)], max_depth=2
        ),
        expected=lambda sts: len(sts) == 1 and
                            not sts[0].regs.edi.concrete and
                            sts[0].solver.eval(sts[0].regs.edi.args[0]) == 5 and\
                            sts[0].regs.edi.op== '__add__'
    )
]

@pytest.mark.parametrize("test_case", BACKWARD_SIMULATOR_TEST_CASES, indirect=True)
def test_backward_simulation(test_case):
    p = angr.Project(test_case.binary, auto_load_libs=False)
    simulator = test_case.simulator(p)
    found = simulator.simulate()
    assert test_case.expected(found)


def test_hook_simulation():
    asm_filepath = fullpath(SIMULATOR_DIR, "hook.s")
    bin_filepath = asm_filepath.replace('.s', '.o')
    subprocess.run(["as", "--64", "-o", bin_filepath , asm_filepath], check=True)

    p = angr.Project(bin_filepath, auto_load_libs=False)
    context = [10]

    stop_condition = lambda sts: len(context) == context[0] and sts[0].addr == 0x40_005c
    initial_values = {Register(p, 'edi', 0x40_0057): context[0]}
    hook_action = lambda sts: context.append(sts.solver.eval(sts.regs.edi))
    hook_condition = lambda st: st.addr == 0x40_0027

    simulator=HookSimulation(
        project=p,
        init_addr=0x40_0057,
        stop=stop_condition,
        event_type='instruction',
        initial_values=initial_values,
        action=hook_action,
        when=angr.BP_BEFORE,
        condition=hook_condition
    )

    states_found = simulator.simulate()
    assert all(arg == context[0]-i for arg, i in enumerate(context))
    assert len(states_found) == 1
    assert states_found[0].solver.eval(states_found[0].regs.rax) == prod(context)
