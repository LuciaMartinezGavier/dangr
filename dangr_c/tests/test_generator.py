import pytest

from dangr_c.code_generator import DangrGenerator
from dangr_c.parser import DangrParser
from dangr_c.jasm_rule import JasmRuleEditor

# TODO: the jasm rule doesnt make much sense
GENERATION_TESTS = [
    (
        'test_files/hardware_breakpoint.yaml',
        DangrGenerator({
        'meta': {},
        'config': {'solve_arguments': True},
        'jasm_rule': {
            'pattern': [{'call': ['@any', '<ptrace@plt>'],
            'address-capture': 'ptrace_call'}]
        },
        'assigns': [
            'a1 = vf.create_from_argument(Argument(1, ptrace_call, 4))',
            'a3 = vf.create_from_argument(Argument(3, ptrace_call, 4))'],
        'variables': ['a1', 'a3'],
        'deps': [],
        'constraints': ['Eq(a1, 3)', 'Eq(a3, 848)'],
        'satisfiable': True,
        'msg': 'Debugging evasion through hardware breakpoint detection'
    }),
    'test_files/hardware_breakpoint.py'
    )
]

@pytest.mark.parametrize("rule_path,expected_dangr_code,expected_gen", GENERATION_TESTS)
def test_parser_and_gen(rule_path, expected_dangr_code, expected_gen):
    parser = DangrParser(rule_path)
    dangr_code_gen = parser.parse_dangr()

    assert dangr_code_gen.intermediate_repr == expected_dangr_code.intermediate_repr
    with open(expected_gen, 'r', encoding='utf-8') as file:
        expected_generated = file.read()
    assert expected_generated == dangr_code_gen.generate_code()
