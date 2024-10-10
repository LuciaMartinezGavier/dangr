import angr
import claripy
from typing import Any

Address = int
Path = str
CFGNode = angr.knowledge_plugins.cfg.cfg_node.CFGNode
AngrExpr = claripy.ast.bv.BV | claripy.ast.bool.Bool
BYTE_SIZE = 8
ALLIGNMENT_OFFSET = 4
