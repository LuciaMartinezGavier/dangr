"""
This is a mocked version of JASM
It will be modified and correctly implemented when
JASM has support for some functionalities I need
which is already in progres but not finished.
"""

import os
from typing import Any, cast
import json
from dataclasses import dataclass
from dangr_rt.dangr_types import Address


def load_json(file_path: str) -> dict[str, Any] | None:
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        return cast(dict[str, Any], data)
    except json.JSONDecodeError as e:
        print("Error decoding JSON:", e)
        return None
    except FileNotFoundError:
        print("File not found:", file_path)
        return None
    except IsADirectoryError:
        print("Invalid file", file_path)
        return None

@dataclass
class VariableMatch:
    name: str
    value: str
    addr: int

@dataclass
class AddressMatch:
    name: str
    value: int

# jasm returns a set of JasmMatch's
class JasmMatch:
    def __init__(
        self,
        match: dict[int, str],
        variables: list[VariableMatch],
        address_captures: list[AddressMatch]
    ) -> None:
        self._match = match
        self._variables = variables
        self._address_captures = address_captures

    @property
    def variables(self) -> list[VariableMatch]:
        """
        Returns a dict with all the variables matched
        Including
        - The variable name
        - The register/literal matched
        - The address capture in the instruction if it exists
        """
        return self._variables

    @property
    def address_captures(self) -> list[AddressMatch]:
        """
        Returns a list with all the address captures.
        The keys are the anchore's names and the value is the match
        """
        return self._address_captures

    def addrmatch_from_name(self, capture_name: str) -> AddressMatch:
        for addr_capt in self._address_captures:
            if addr_capt.name == capture_name:
                return addr_capt
        raise ValueError("Invalid capture name")

    def varmatch_from_name(self, capture_name: str) -> VariableMatch:
        for varmatch in self._variables:
            if varmatch.name == capture_name:
                return varmatch
        raise ValueError("Invalid capture name")

    @property
    def start(self) -> Address:
        return list(self._match.keys())[0]

    @property
    def end(self) -> Address:
        return list(self._match.keys())[-1]

def cast_var_value(var_value: str | int) -> int | str:
    try:
        return int(var_value, 16)
    except ValueError:
        return var_value

def _parse_jasm_output(jasm_out: list[dict[str, Any]]) -> list[JasmMatch]:
    all_matches = []
    for j_match in jasm_out:
        out_match = {}
        out_vars = []
        out_addr_capt = []
        for m in j_match['match']:
            addr, instr = m.split("::")
            out_match[int(addr, 16) + 0x40_0000] = instr

        for name_capt, info_capt in j_match['name-captures'].items():
            out_vars.append(
                VariableMatch(
                    name=name_capt,
                    value=cast_var_value(info_capt[0]),
                    addr=int(info_capt[1], 16) + 0x40_0000
                )
            )
        for addr_capt, info_capt in j_match['address-captures'].items():
            out_addr_capt.append(
                AddressMatch(
                    name=addr_capt,
                    value=int(info_capt, 16) + 0x40_0000
                ))

        all_matches.append(
            JasmMatch(
                match=out_match,
                variables=out_vars,
                address_captures=out_addr_capt
        ))

    return all_matches

constraint_bug_matches = [JasmMatch( {0x40_1144: "", 0x401147: "", 0x40_114a: ""}, [
    VariableMatch('x', 'edx', 0x40_114a),
    VariableMatch('y', 'eax', 0x40_114a)], []
)]


mock_small_bmp_support_lib = {
    '1339': [ JasmMatch(
        match={0x40_1339:''},
        address_captures=[AddressMatch(name="alloc_call", value=0x40_1339)],
        variables=[])],
    '12c5': [ JasmMatch(
        match={0x40_12c5:''},
        address_captures=[AddressMatch(name="alloc_call", value=0x40_12c5)],
        variables=[])]
}

mock_hardware_breakpoint = {
    '11f3': [ JasmMatch(
        match={0x40_11f3:''},
        address_captures=[AddressMatch(name="ptrace_call", value=0x40_11f3)],
        variables=[]
    )]
}

mock_software_breakpoint = {
    '0038': [JasmMatch(
        match={
            0x40_002b: "some_instruction",
            0x40_0038: "some_instruction"
        },
        address_captures=[
            AddressMatch(name='cmp-address', value=0x40_0038)
        ],
        variables=[
            VariableMatch(name="ptr",value='rax', addr=0x40_002b),
            VariableMatch('y', value=0xf223, addr=0x40_0038),
            VariableMatch(name='z', value='eax', addr=0x40_0038)
        ]
    )],
    '0002': [JasmMatch(
        match={
            0x40_0000: 'some_instruction',
            0x40_0002: 'some_instruction'
        },
        address_captures=[AddressMatch(name='cmp-address', value=0x40_0002)],
        variables=[
            VariableMatch(name='ptr', value='rdi', addr=0x40_0000),
            VariableMatch(name='y', value=0xfa1e0ff3, addr=0x40_0002),
            VariableMatch(name='z', value='eax', addr=0x40_0002)
        ],
    )],
    '0021': [JasmMatch(
        match={0x40_0014:'ignore', 0x40_0021: 'ignore'},
        address_captures=[AddressMatch(name='cmp-address', value=0x40_0021)],
        variables=[
            VariableMatch(name='ptr', value='rax', addr=0x40_0014),
            VariableMatch(name='y',   value='edx', addr=0x40_0021),
            VariableMatch(name='z',   value='eax', addr=0x40_0021)
        ]
    )],
    'd490': [JasmMatch(
        match={0x40_d48e:'', 0x40_d490:''},
        address_captures=[AddressMatch(name='cmp-address', value=0x40_d490)],
        variables=[
            VariableMatch(name='ptr', value='rdi', addr=0x40_d48e),
            VariableMatch(name='y', value='edx', addr=0x40_d490),
            VariableMatch(name='z', value='eax', addr=0x40_d490)
        ]
    )]
}

mock_uncontrolled_input = {
    '0078' : [JasmMatch(
            match={0x40_0059:'', 0x40_0078: ''},
            address_captures=[AddressMatch(name='deref-address', value=0x40_0078)],
            variables=[VariableMatch(name='ptr', value='rax', addr=0x40_0078)]
        )],
    '00ce': [JasmMatch(
            match={0x40_00be: '', 0x40_00ce: ''},
            address_captures=[AddressMatch(name='deref-address', value= 0x40_00ce)],
            variables=[VariableMatch(name='ptr', value='rax', addr=0x40_00ce)]
        )],
    '00b5': [JasmMatch(
            match={0x40_0081:'', 0x40_00b5: ''},
            address_captures=[AddressMatch(name='deref-address', value=0x40_00b5)],
            variables=[VariableMatch(name='ptr', value='rax', addr=0x40_00b5)]
        )],
    '0125': [JasmMatch(
            match={0x40_0109:'', 0x40_0125: ''},
            address_captures=[AddressMatch(name='deref-address', value=0x40_0125)],
            variables=[VariableMatch(name='ptr', value='rax', addr=0x40_0125)]
        )]
}

def _run_jasm(jasm_pattern: str, binary_path: str) -> list[JasmMatch]:
    path_to_mock = os.path.join(os.path.dirname(__file__), "jasm_mock")
    _ = binary_path
    match jasm_pattern:
        case 'software_breakpoint_pattern':
            path_to_mock = os.path.join(path_to_mock, "sw_brk_jasm_out.json")
            jasm_match_uparsed = load_json(path_to_mock)
            return _parse_jasm_output(jasm_match_uparsed)
        case 'mock constraint_bug':
            return constraint_bug_matches
        case 'mock small_bmp_support_lib_12c5':
            return mock_small_bmp_support_lib['12c5']
        case 'mock small_bmp_support_lib_1339':
            return mock_small_bmp_support_lib['1339']
        case 'mock hardware_breakpoint':
            return mock_hardware_breakpoint['11f3']
        case 'mock software_breakpoint_0038':
            return mock_software_breakpoint['0038']
        case 'mock software_breakpoint_0002':
            return mock_software_breakpoint['0002']
        case 'mock software_breakpoint_0021':
            return mock_software_breakpoint['0021']
        case 'mock software_breakpoint_d490':
            return mock_software_breakpoint['d490']
        case 'mock uncontrolled_input_0078':
            return mock_uncontrolled_input['0078']
        case 'mock uncontrolled_input_00ce':
            return mock_uncontrolled_input['00ce']
        case 'mock uncontrolled_input_00b5':
            return mock_uncontrolled_input['00b5']
        case 'mock uncontrolled_input_0125':
            return mock_uncontrolled_input['0125']
        case _:
            raise ValueError("We are still working on this! "
            "Try using 'software_breakpoint_pattern' to get a mocked answer")


class JasmAPI:
    def __init__(self) -> None:
        pass

    def run(self, binary_path: str, jasm_pattern) -> list[JasmMatch]:
        jasm_matches = _run_jasm(jasm_pattern, binary_path)
        return jasm_matches

