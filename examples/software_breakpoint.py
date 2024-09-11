from dangrlib import DangrAnalysis, structural_filter

def some_solution(values) -> bool:
    return any(value["dx"] == 0xFA1E0FF3 for value in values)


def detect(binary_path: str, jasm_pattern: str):
    jasm_out = structural_filter(binary_path, jasm_pattern)

    dangr = DangrAnalysis(
        max_depht=10,
        binary_path=binary_path,
        jasm_out=jasm_out
    )

    for structural_finding in jasm_out:
        set_finding(structural_finding)

        registers_used = dang.args_used()
        dangr.concrete_fn_args(registers_used)

        dangr.simulate(jasm_out.addresses[-1])

        if not (dependency("y", "dx") or dependency("z", "dx")):
            break

        dangr.add_constraint(Constraint(op='=', lh='y', rh='z'))

        concrete_values = dangr.concrete(Memory("dx"))

        if some_solution(concrete_values):
            print("Debuggind evasion trough Software breakpoint detection")
            return

