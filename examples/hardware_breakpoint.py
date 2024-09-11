from dangrlib import DangrAnalysis


def some_solution(args_values) -> bool:
    return any([value["a1"] == 3 and value["a3"] == 848 for value in args_values])


def detect(binary_path: str, jasm_pattern: str) -> bool:
    jasm_out = structural_filter(binary_path, jasm_pattern)

    dangr = DangrAnalysis(
        max_depht=10,
        binary_path=binary_path,
    )

    for structural_finding in jasm_out:
        set_finding(structural_finding)

        registers_used = dang.args_used()
        dangr.concrete_fn_args(registers_used)

        # TODO: decide how is the address to find
        dangr.simulate(jasm_out.addresses[-1])

        # NOTE: this depends on how the `then` formula is written
        # if the variables are in the same formula, they are evaluated together
        args_values = concrete([Argument(1, "ptrace", "a1"), Argument(1, "ptrace", "a3")])

        if some_solution(args_values):
            print("Debuggind evation trough hardware breakpoint detection")
            return True

    return False
