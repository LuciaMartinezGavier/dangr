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

def _run_jasm(jasm_pattern: str, binary_path: str) -> list[JasmMatch]:
    path_to_mock = os.path.join(os.path.dirname(__file__), "jasm_mock")
    _ = binary_path
    match jasm_pattern:
        case 'software_breakpoint_pattern':
            path_to_mock = os.path.join(path_to_mock, "sw_brk_jasm_out.json")
        case _:
            raise ValueError("We are still working on this! "
            "Try using 'software_breakpoint_pattern' to get a mocked answer")

    jasm_match_uparsed = load_json(path_to_mock)
    return _parse_jasm_output(jasm_match_uparsed)


def structural_filter(binary_path: str, jasm_pattern) -> list[JasmMatch]:
    jasm_matches = _run_jasm(jasm_pattern, binary_path)
    return jasm_matches
