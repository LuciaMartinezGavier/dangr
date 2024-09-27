from dangr_analysis import DangrAnalysis
from variables import ConcreteState, Argument, Variable
from jasm_findings import structural_filter

def some_solution(concrete_states: list[ConcreteState], a1: Variable, a3: Variable) -> bool:
    return any(concr.get_value(a1) == 3 and concr.get_value(a3) == 848 for concr in concrete_states)


def detect(binary_path: str, jasm_pattern: str) -> bool:
    s_findings = structural_filter(binary_path, jasm_pattern)
    dangr = DangrAnalysis(binary_path, max_depth=10)

    for struc_find in s_findings:
        dangr.set_finding(struc_find)

        ptrace_call = struc_find.address_captures["ptrace_call"]
        vf = dangr.get_variable_factory()
        a1 = vf.create_from_argument(Argument(1, ptrace_call))
        a3 = vf.create_from_argument(Argument(3, ptrace_call))
        dangr.add_variables([a1, a3])

        list_concrete_values = dangr.concretize_fn_args()

        found_states = dangr.simulate(ptrace_call, list_concrete_values)

        if not found_states:
            return False

        concrete_states = []
        a1_values = a1.evaluate()
        a3_values = a3.evaluate()

        all_states = set(a1_values.keys()).union(a3_values.keys())

        for state in all_states:
            concrete_state = ConcreteState()
            concrete_state.add_value(a1, a1_values[state])
            concrete_state.add_value(a3, a3_values[state])
            concrete_states.append(concrete_state)

        if some_solution(concrete_states, a1, a3):
            print("Debuggind evation trough hardware breakpoint detection")
            return True

    return False

detect('/home/luciamg/debug_detection2/tests/test_files/hardware_breakpoint', '')
