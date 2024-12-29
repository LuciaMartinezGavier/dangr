import pytest

from dangr_c.code_generator import DangrGenerator
from dangr_c.parser import DangrParser
from dangr_c.jasm_rule import JasmRuleEditor

GENERATION_TESTS = [
    ('test_files/hardware_breakpoint.yaml', 'test_files/hardware_breakpoint.py'),
    ('test_files/software_breakpoint.yaml', 'test_files/software_breakpoint.py'),
    ('test_files/alloc_zero.yaml', 'test_files/alloc_zero.py'),
    ('test_files/uncontrolled_usr_input.yaml', 'test_files/uncontrolled_usr_input.py'),
]

@pytest.mark.parametrize("rule_path,expected_gen", GENERATION_TESTS)
def test_parser_and_gen(rule_path, expected_gen):
    parser = DangrParser(rule_path)
    dangr_code_gen = parser.parse_dangr()

    with open(expected_gen, 'r', encoding='utf-8') as file:
        expected_generated = file.read()
    assert expected_generated == dangr_code_gen.generate_code()
