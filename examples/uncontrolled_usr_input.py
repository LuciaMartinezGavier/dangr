from dangrlib import DangrAnalysis, structural_filter

def detect(binary_path: str, jasm_pattern: str):
    jasm_out = structural_filter(binary_path, jasm_pattern)

    dangr = DangrAnalysis(binary_path=binary_path, jasm_out=jasm_out)

    for structural_finding in jasm_out:
        set_finding(structural_finding)
        args_used = dangr.args_used()
        dangr.simulate(structural_finding.adresses[-1])

        if not any(dependency(arg, ptr) for arg in args_used):
            break

        if upper_unbounded(Formula(ptr + idx*size)):
            break
        
        return True

    return False
