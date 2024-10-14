import angr
import claripy
from typing import Any
from dataclasses import dataclass

Address = int
Path = str
CFGNode = angr.knowledge_plugins.cfg.cfg_node.CFGNode
RegOffset = int

BV = claripy.ast.bv.BV
Bool = claripy.ast.bool.Bool

AngrExpr = BV | Bool
BYTE_SIZE = 8

@dataclass
class Argument:
    """
    A data class representing an argument in a function call.
    """
    idx: int
    call_address: Address
    size: int
