from dangr_analysis import DangrAnalysis
from jasm_findings import structural_filter
from variables import ConcreteState, Deref, Variable
from expression import EqualNode, VarNode

def some_solution(concrete_states: list[ConcreteState], dx: Variable) -> bool:
    return any(0xf30f1efa == concr.get_value(dx) for concr in concrete_states)

def detect(binary_path: str, jasm_pattern: str):
    s_findings = structural_filter(binary_path, jasm_pattern)
    dangr = DangrAnalysis(binary_path, max_depth=10)

    for struc_find in s_findings:
        dangr.set_finding(struc_find)

        cmp_address = struc_find.address_captures["cmp-address"]
        vf = dangr.get_variable_factory()
        ptr = vf.create_from_capture(struc_find.captured_regs['ptr'])

        y = vf.create_from_capture(struc_find.captured_regs['y'])
        z = vf.create_from_capture(struc_find.captured_regs['z'])
        dx = Deref(ptr.reference_address, ptr)
        dangr.add_variables([y,z,dx])

        if not (dangr.depends(dx, y) or dangr.depends(dx, z)):
            break

        list_concrete_values = dangr.concretize_fn_args()

        dangr.add_constraint(EqualNode(lh=VarNode(y), rh=VarNode(z)))
        found_states = dangr.simulate(cmp_address, list_concrete_values)

        if not found_states:
            return False

        dx_values = []
        for state in found_states:
            dx_values.extend(dx.evaluate_memory(state))

        concrete_states = []
        for dx_value in dx_values:
            concrete_state = ConcreteState()
            concrete_state.add_value(dx, dx_value)
            concrete_states.append(concrete_state)

        if some_solution(concrete_states,dx):
            print("Debuggind evasion trough Software breakpoint detection")
            return

detect('/home/luciamg/debug_detection2/tests/test_files/liblzma.so.5.6.1', '')
