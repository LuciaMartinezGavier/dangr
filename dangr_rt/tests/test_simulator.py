
from dataclasses import dataclass
from math import prod
from typing import Final, Callable, Any
import pytest
import angr

from tests.conftest import BinaryBasedTestCase

from dangr_rt.variables import Register, Memory
from dangr_rt.dangr_types import Address
from dangr_rt.simulator import Simulator, ForwardSimulation, StepSimulation, BackwardSimulation, HookSimulation, ConcreteState


@dataclass(kw_only=True)
class SimulatorTestCase(BinaryBasedTestCase):
    simulator: Callable[angr.Project, Simulator]
    expected: Callable[list[angr.SimState], bool] | Callable[[list[angr.SimState], int], bool]
    init_state: Callable[angr.Project, ConcreteState] | None = None
    targets: list[Address] | None = None # only for step simulations
    files_directory: str = 'simulator'

FOO: Final = 539
BAR: Final = 324
MEM: Final = 0xc0ca_c01a
ARR: Final = [5, 8, 2, 6, 3]

context = [10]

def array_to_hex(arr):
    hex_string = "0x"
    for num in arr:
        hex_string += f"{num:02x}_00_00_00_"
    return int(hex_string.rstrip('_'), 16)


def step_validate(states, step):
    if not len(states) == 1 and states[0].regs.edi.concrete:
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

SIMULATOR_TESTS: Final = [
    SimulatorTestCase(
        asm_filename='forward.s',
        simulator=lambda p: ForwardSimulation(p, 0x40_00d4, 0x40_0182),
        expected=lambda sts:\
            len(sts) == 1 and\
            sts[0].regs.rax.concrete and\
            sts[0].memory.load(MEM, 4).concrete and\
            sts[0].solver.eval(sts[0].regs.rax) == FOO + BAR and\
            sts[0].solver.eval(sts[0].memory.load(MEM, 4)) == 0,
        init_state=lambda p: {
            Register(p, 'edi', 0x40_00dc): 1,
            Register(p, 'rsi', 0x40_00df): FOO,
            Register(p, 'rdx', 0x40_00e3): BAR,
            Register(p, 'rcx', 0x40_00e7): MEM
        }
    ),
    SimulatorTestCase(
        asm_filename='forward.s',
        simulator=lambda p: ForwardSimulation(p, 0x40_00d4, 0x40_0182),
        expected=lambda sts:\
            len(sts) == 1 and\
            sts[0].regs.rax.concrete and\
            sts[0].memory.load(MEM, 4).concrete and\
            sts[0].solver.eval(sts[0].regs.rax) == 0 and\
            # NOTE: `reversed` because Intel uses little endian
            sts[0].solver.eval(sts[0].memory.load(MEM, 4).reversed) == 1,
        init_state=lambda p: {
            Register(p, 'edi', 0x40_00dc): 4,
            Register(p, 'rsi', 0x40_00df): FOO,
            Register(p, 'rdx', 0x40_00e3): 0,
            Register(p, 'rcx', 0x40_00e7): MEM
        }
    ),
    SimulatorTestCase(
        asm_filename='forward.s',
        simulator=lambda p: ForwardSimulation(p, 0x40_00d4, 0x40_0182),
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
        init_state=lambda p: {
            Register(p, 'edi', 0x40_00dc): 4,
            Register(p, 'rcx', 0x40_00e7): MEM,
        }
    ),
    SimulatorTestCase(
        asm_filename='step.s',
        simulator=lambda p: StepSimulation(p, 0x40_000a),
        expected=step_validate,
        targets=[0x40_0063, 0x40_00a1, 0x40_00f4, 0x40_017f],
        init_state=lambda p: {
            Memory(p, MEM, len(ARR)*4, 0x40_000a): array_to_hex(ARR),
            Register(p, 'rdi', 40_0012): MEM,
            Register(p, 'esi', 40_0016): len(ARR)
        }
    ),
    SimulatorTestCase(
        asm_filename='hook.s',
        simulator=lambda p: HookSimulation(
            p, 0x40_0057, 'instruction',
            action=lambda sts: context.append(sts.solver.eval(sts.regs.edi)),
            when=angr.BP_BEFORE,
            stop=lambda sts: len(context) == context[0] and sts[0].addr == 0x40_005c,
            condition=lambda st: st.addr == 0x40_0027
        ),

        expected=lambda states: all(arg == context[0]-i for arg, i in enumerate(context)) and\
                                len(states) == 1 and\
                                states[0].solver.eval(states[0].regs.rax) == prod(context),
        init_state=lambda p: {Register(p, 'edi', 0x40_0057): context[0]}
    ),
    SimulatorTestCase(
        asm_filename='backward.s',
        simulator=lambda p: BackwardSimulation(
            p, 0x40_0000, p.analyses.CFGFast(),
            [Register(p, 'edi', 0x40_0004)], max_depth=5
        ),
        expected=lambda sts: len(sts) == 1 and\
                             sts[0].regs.edi.concrete and\
                             sts[0].solver.eval(sts[0].regs.edi) == 6,
    ),
    SimulatorTestCase(
        asm_filename='backward.s',
        simulator=lambda p: BackwardSimulation(
            p, 0x40_0000, p.analyses.CFGFast(),
            [Register(p, 'edi', 0x40_0004)], max_depth=2
        ),
        expected=lambda sts: len(sts) == 1 and
                            not sts[0].regs.edi.concrete and
                            sts[0].solver.eval(sts[0].regs.edi.args[0]) == 5 and\
                            sts[0].regs.edi.op== '__add__'
    )
]

@pytest.mark.parametrize("test_case", SIMULATOR_TESTS, indirect=True)
def test_simulation(test_case):
    """
    Simulates a chunk and checks for properties in the resulting states
    """
    p = angr.Project(test_case.binary, auto_load_libs=False)
    simulator = test_case.simulator(p)

    if test_case.init_state:
        simulator.set_initial_values(test_case.init_state(p))

    if test_case.targets is None:
        found = simulator.simulate()
        assert test_case.expected(found)
        return

    for i, target in enumerate(test_case.targets):
        simulator.set_step_target(target)
        found = simulator.simulate()
        assert test_case.expected(found, i)
