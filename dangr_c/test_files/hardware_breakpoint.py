"""
# Automatically generated code for binary analysis using 'dangr_c'.
#
# the Rule class extends the DangrAnalysis, which defines a method
# analize(jasm_pattern) which uses asm pattern-matching
# to detect specific structural findings in the binary,
# and then they are analyzed through symbolic execution and 
# constraint solving.
"""

import sys
from typing import Final, override
from dangr_rt import *


class Rule(DangrAnalysis):

    @override
    @property
    def _jasm_pattern(self) -> dict:
        return {'pattern': 'mock hardware_breakpoint'}

    @override
    @property
    def meta(self) -> dict:
        return {}

    @override
    def _analyze_asm_match(self, jasm_match: JasmMatch) -> str | None:
        msg = "Debugging evasion through hardware breakpoint detection"
        ptrace_call = jasm_match.addrmatch_from_name("ptrace_call").value
        _target = jasm_match.addrmatch_from_name("_target").value
        a1 = self._create_var_from_argument(Argument(1, ptrace_call, 4))
        a3 = self._create_var_from_argument(Argument(3, ptrace_call, 4))
        self._add_constraint(Eq(a1, 3))
        self._add_constraint(Eq(a3, 848))
        args_list = self._concretize_fn_args()

        for args in args_list:
            found_states = self._simulate(_target, args)
            if self._satisfiable(found_states):
                return msg


if __name__ == "__main__":
    parser = DangrArgparse(
        "Run binary analysis and detect a beheavorial pattern")
    parser.add_argument("-b",
                        "--binary-path",
                        type=str,
                        required=True,
                        help="Path to binary to analyze.")

    args = parser.dangr_parse_args()
    rule = Rule(args.binary_path, args.config)
    report = rule.analyze()

    if report:
        print(report)
        sys.exit(1)

    sys.exit(0)
