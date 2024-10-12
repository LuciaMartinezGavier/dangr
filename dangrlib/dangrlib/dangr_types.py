import angr
import claripy
from typing import Any
from dataclasses import dataclass

Address = int
Path = str
CFGNode = angr.knowledge_plugins.cfg.cfg_node.CFGNode
AngrExpr = claripy.ast.bv.BV | claripy.ast.bool.Bool
BYTE_SIZE = 8
ALLIGNMENT_OFFSET = 4


@dataclass
class Argument:
    """
    A data class representing an argument in a function call.
    """
    idx: int
    call_address: Address
    size: int
