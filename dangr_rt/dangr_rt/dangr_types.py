from dataclasses import dataclass
import angr
import claripy

Address = int
Path = str
CFGNode = angr.knowledge_plugins.cfg.cfg_node.CFGNode
RegOffset = int

AngrArith = claripy.ast.bv.BV | int
AngrBool = claripy.ast.bool.Bool | bool

AngrExpr = AngrArith | AngrBool
BYTE_SIZE = 8

@dataclass
class Argument:
    """
    A data class representing an argument in a function call.
    """
    idx: int
    call_address: Address
    size: int
