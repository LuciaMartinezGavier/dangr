from jasm_findings import structural_filter
from dangr_analysis import DangrAnalysis
from expression import SumNode, MultNode, VarNode

def detect(binary_path: str, jasm_pattern: str):
    s_findings = structural_filter(binary_path, jasm_pattern)

    dangr = DangrAnalysis(binary_path)
    print(s_findings)
    for struc_find in s_findings:
        print("HI")
        dangr.set_finding(struc_find)
        vf = dangr.get_variable_factory()

        ptr = vf.create_from_capture(struc_find.captured_regs['ptr'])
        # idx = vf.create_from_capture(struc_find.captured_regs['idx'])
        # size = vf.create_from_capture(struc_find.captured_regs['size'])
        dangr.add_variables([ptr])
        deref_address = struc_find.address_captures["deref-address"]
        args = dangr.get_fn_args()
        if all(not dangr.depends(arg, ptr) for arg in args):
            break

        found_states = dangr.simulate(deref_address)

        if not dangr.upper_bounded(VarNode(ptr), found_states): #, MultNode(idx,size))):
            print("Uncontrolled user input could lead to SMM memory corruption")
            return True

    return False

detect('/home/luciamg/dangr/tmp/uncontrolled_usr_input','')