from dangr_rt.dangr_analysis import DangrAnalysis
from dangr_rt.jasm_findings import structural_filter
from dangr_rt.expression import *
from dangr_rt.dangr_types import Argument

JASM_PATTERN: dict = {'pattern': [{'call': ['@any', '<ptrace@plt>'], 'address-capture': 'ptrace_call'}]}

def detect(binary_path: str, max_depth: int) -> bool:
    s_findings = structural_filter(binary_path, JASM_PATTERN)
    dangr = DangrAnalysis(binary_path, max_depth)
    vf = dangr.get_variable_factory()

    for s_finding in s_findings:
        dangr.set_finding(s_finding)
        ptrace_call = s_finding.address_captures["ptrace_call"]
        _target = s_finding.address_captures["_target"]
        a1 = vf.create_from_argument(Argument(1, ptrace_call, 4))
        a3 = vf.create_from_argument(Argument(3, ptrace_call, 4))

        dangr.add_variables([a1, a3])
        dangr.add_constraint(Eq(a1, 3))
        dangr.add_constraint(Eq(a3, 848))
        concrete_values = dangr.concretize_fn_args()
        found_states = dangr.simulate(_target, concrete_values)
        if not found_states:
            return False
        if not dangr.satisfiable(found_states):
            print("Debugging evation through hardware breakpoint detection")
            return True

    return False