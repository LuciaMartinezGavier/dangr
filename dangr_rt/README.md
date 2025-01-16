# Dangr Runtime Library

**`dangr_rt`** is the runtime library for **Dangr**, a declarative language designed for semantic pattern detection in binary analysis. Built on top of the **angr** framework, this library provides the necessary abstractions and methods to facilitate symbolic execution, static analysis, and semantic property verification over binary code. Its primary purpose is to simplify the generation and execution of compiled Dangr rules while maintaining a close resemblance to the declarative syntax.


## Features

- **Pattern Detection**: Analyze binary files to detect patterns defined using Dangr rules.
- **Dependency Verification**: Validate dependencies between variables in a binary.
- **Symbolic Execution**: Simulate binary execution to explore paths and enforce constraints.
- **Argument Analysis**: Retrieve concrete values for function arguments during analysis.
- **Customizable Workflow**: Extend the core analysis through inheritance and custom methods.


## Workflow

To use `dangr_rt`, extend the base class `DangrAnalysis` to define a custom detection workflow. Example:

```python
from dangr_rt import DangrAnalysis

class MyAnalysis(DangrAnalysis):
    def _analyze_asm_match(self, jasm_math):
        # define the analysis here
        msg = "Alloc can be called with 0 as argument"
        alloc_call = jasm_match.addrmatch_from_name("alloc_call").value
        _target = jasm_match.addrmatch_from_name("_target").value
        size = self._create_var_from_argument(Argument(1, alloc_call, 4))
        self._add_constraint(Eq(size, 0))
        found_states = self._simulate(_target)
        if self._satisfiable(found_states):
            return msg
```
**Core Analysis Workflow:**

1. **Initialization**: Load the binary, generate the Control Flow Graph (CFG), and set up the symbolic analysis environment.
2. **Pattern Matching**: Use [JASM](https://github.com/JukMR/JASM) for static pattern detection.
3. **Dependency Analysis**: Verify relationships between variables using the `DependencyAnalyzer`.
4. **Symbolic Execution**: Apply constraints and simulate binary execution using `DangrSimulation`.
5. **Result Interpretation**: Evaluate the satisfiability of final execution states.

![Sequence_diagram](design/sequence.png)


## Architecture and Design

![arquitecture](design/class_diagram.png)

### DangrAnalysis
`DangrAnalysis` uses the **template method** design pattern. The skeleton of the analysis is defined in the `analyze()` method, while specific steps, such as symbolic execution or dependency checks, are delegated to subclasses. Users can override the `_analyze_asm_match()` method to implement custom logic.

![DangrAnalysis](design/dangr_analysis.png)

### VariableFactory
Generates `Variable` objects, representing binary-specific elements like registers, memory, literals, or dereferences.

![Variable](design/variables.png)

### DependencyAnalyzer
Provides methods to check if a variable depends on another, enabling fine-grained semantic verification.

![DependencyAnalyzer](design/dependency_analyzer.png)

### DangrSimulation
Handles symbolic execution, applying constraints and exploring execution paths. Implements the methods `add_constraint()` and `simulate()`

Dangr Simulation uses symbolic execution to analyze binaries and verify program properties. Built on angr, it allows users to define constraints and explore execution paths dynamically.

**Key features:**
- **Symbolic Execution:** Variables are represented symbolically, and constraints are translated into SMT queries with Z3 to check feasibility (done by angr).
- **Constraints:** Defined as boolean or arithmetic expressions, constraints guide simulation by restricting states at specific checkpoints.
- **Execution Workflow:** Simulation starts at a function’s entry and uses checkpoints to associate variables or apply constraints. Diverging paths are analyzed independently, discarding unsatisfiable states.
- **Optimizations:** Configurable timeouts and state limits ensure efficient analysis.

### ArgumentAnalyzer
Recovers the concrete values of function arguments for further analysis.

![ArgumentAnalyzer](design/argument_analyzer.png)
