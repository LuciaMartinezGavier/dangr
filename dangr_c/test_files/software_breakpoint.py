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
    def _jasm_pattern(self) -> dict:
        return {'pattern': 'software_breakpoint_pattern'}

    @override
    def meta(self) -> dict:
        return {}

    @override
    def _analyze_asm_match(self, jasm_match: JasmMatch) -> str | None:
        msg = "Debugging evasion through software breakpoint detection"
        _target = jasm_match.addrmatch_from_name("_target").value
        cmp_operand_1 = self._create_var_from_capture(
            jasm_match.varmatch_from_name("cmp_operand_1"))
        cmp_operand_2 = self._create_var_from_capture(
            jasm_match.varmatch_from_name("cmp_operand_2"))
        opcode_addr = self._create_var_from_capture(
            jasm_match.varmatch_from_name("opcode_addr"))
        opcode = self._create_deref(opcode_addr)
        if not (self._depends(opcode, cmp_operand_1)
                or self._depends(opcode, cmp_operand_2)):
            return
        self._add_constraint(Eq(cmp_operand_1, cmp_operand_2))
        self._add_constraint(Not(Eq(opcode, 0xFA1E0FF3)))
        args_list = self._concretize_fn_args()

        for args in args_list:
            found_states = self._simulate(_target, args)
            if not found_states:
                return msg if self._unconstrained_sat(_target, args) else None

            if not self._satisfiable(found_states):
                return msg


if __name__ == "__main__":
    parser = DangrArgparse("Run binary analysis")
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
