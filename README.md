# ⚠️ Dangr: Language for Finding Behavioral Patterns in Binaries Using Symbolic Execution 

## Introduction
As software systems become increasingly complex, vulnerabilities and cyberattacks are on the rise. Traditional static analysis tools struggle to detect obfuscated or compiler-optimized code, creating a need for more advanced techniques. Symbolic execution offers a solution, but no tool currently generalizes these detections. There is a clear need for a tool that simplifies the process of detecting behaviors in binaries using symbolic execution and solvers.

This thesis will contribute a new declarative language, Dangr, for finding behavioral patterns in binaries using symbolic execution and solvers. The tool's ability to detect and deobfuscate opaque constants will provide significant benefits in vulnerability discovery and malware analysis, enhancing the capability to detect indicators of compromise.


## Abstract
This thesis proposes the design and implementation of a domain-specific declarative language, Dangr, designed to describe behavioral patterns found in binaries. Dangr code will be transpiled to Python code that uses the binary analysis platform angr, combining symbolic execution with static analysis. This DSL simplifies the process of automatically identifying both obfuscated indicators of compromise and vulnerabilities that are not easily detectable through static analysis alone.


## Proposed Solution
Dangr is defined as a declarative language that describes patterns. It has five main sections: `given`, `where`, `such-that`, `then`, and `report`. The `given` section identifies the structural pattern in the binary; the `where` section restricts relationships between components of that pattern; `such-that` sets constraints on variables; `then` expresses a predicate to evaluate; and `report` prints a message if the predicate is true. There is also a `config` section that sets analysis parameters.

Example language constructs:

```yml
config:
  max_backslice_depth: 10
given
  pattern:
    - add:
        - $deref:
            main_reg: "@any-dx"
        - "@any"
    - cmp:
      - "@any-y"
      - pattern: "@any-z"
where:
  - $y -> $dx
such-that:
  - $y = $z
then:
  - $dx == 0xFA1E0FF3
report: "Possible debugging evasion detection"
```

[Read more…](#language-definition)

## Work Plan
1. Introduction and Problem Definition
    1. Literature Review: Research previous work related to pattern detection in binaries, symbolic execution, and the use of solvers.
    2. Identification of Current Limitations: Describe the limitations of current tools like angr in pattern detection.
    3. Project Justification: Explain why a new declarative language, Dangr, is necessary and how it will address current limitations.
2. Design of the Dangr Declarative Language
    1. Language Specification: Define the syntax and semantics of the Dangr language.
        - `config`: Analysis configuration parameters.
        - `given`: Identification of structural patterns in the binary.
        - `where`: Constraints between components of the pattern.
        - `such-that`: Constraints on variables.
        - `then`: Predicates to evaluate.
        - `report`: Report messages when the predicate is true.
3. Implementation of the Dangr-to-Python Transpiler
    1. Requirements Analysis: Define the requirements for the transpiler.
    2. Transpiler Development:
        - Dangr Language Parser: Implement a parser to convert Dangr code into an intermediate representation.
        - Python Code Generation: Transpile the intermediate representation to Python code that uses angr.
    3. Integration with angr: Ensure the generated Python code interacts correctly with the angr platform.
4. Testing and Validation
    1. Test Case Development: Create test cases that cover a variety of patterns and behaviors to detect.
    2. Performance Evaluation:
        - Transpiler Efficiency: Measure the transpilation and execution time of the generated Python code.
        - Detection Effectiveness: Evaluate Dangr's ability to detect patterns and vulnerabilities compared to other methods.
5. Case Study and Applications
    1. Vulnerability Discovery: Use Dangr to identify vulnerabilities in known software binaries.
6. Documentation and Thesis Writing
   1. Thesis Document Writing: Document all findings, language design, implementation, and test results.
   2. Review and Correction: Review and correct the thesis document to ensure clarity and accuracy.

| Plan de Trabajo                        |      |       |        |        |      |      |       |        |        |       |        |        |        |       |       |        |        |       |       |      |       |        |        |
| -------------------------------------- | ---- | ----- | ------ | ------ | ---- | ---- | ----- | ------ | ------ | ----- | ------ | ------ | ------ | ----- | ----- | ------ | ------ | ----- | ----- | ---- | ----- | ------ | ------ |
| Tema\\Semana                           | J1-7 | J8-14 | J15-21 | J21-26 | A5-9 | S2-8 | S9-15 | S16-22 | S23-29 | O30-6 | O7--13 | O14-20 | O21-27 | N28-3 | N4-10 | N11-17 | N18-24 | N25-1 | D25-1 | D2-8 | D9-15 | D16-22 | D23-29 |
| Plan de trabajo                        | x    | x     | x      |        |      |      |       |        |        |       |        |        |        |       |       |        |        |       |       |      |       |        |        |
| Prueba de concepto                     | x    | x     | x      |        |      |      |       |        |        |       |        |        |        |       |       |        |        |       |       |      |       |        |        |
| Introducción y Definición del Problema |      |       |        | x      |      |      |       |        |        |       |        |        |        |       |       |        |        |       |       |      |       |        |        |
| Diseño del Lenguaje Declarativo        | x    | x     |        |        | x    |  x   |       |        |        |       |        |        |        |       |       |        |        |       |       |      |       |        |        |
| Implementación del Transpilador        |      |       |        |        |      |      |   x   | x      | x      | x     | x      | x      |        |       |       |        |        |       |       |      |       |        |        |
| Pruebas y Validación                   |      |       |        |        |      |      |       |        |        |       |        | x      | x      |       |       |        |        |       |       |      |       |        |        |
| Estudio de Caso y Aplicaciones         |      |       |        |        |      |      |       |        |        |       |        |        |        | x     | x     |        |        |       |       |      |       |        |        |
| Documentación y Redacción              |      |       |        |        |      |      |       |        |        |       |        |        |        |       |       | x      | x      | x     | x     | x    |       |        |        |
| Preparación y Defensa                  |      |       |        |        |      |      |       |        |        |       |        |        |        |       |       |        |        |       |       | x    | x     |        |
## References
- Shoshitaishvili, Y., Wang, R., Salls, C., Stephens, N., Polino, M., Dutcher, A., Grosen, J., Feng, S., Hauser, C., Kruegel, C., & Vigna, G. (2016). SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis. In IEEE Symposium on Security and Privacy.
- Oravec, R. (2021). Modern Obfuscation Techniques (Master's thesis). Masaryk University, Faculty of Informatics.
- Mérida Renny, J. (2024). JASM: una herramienta para detectar indicadores de compromiso en binarios (Trabajo Especial). Universidad Nacional de Córdoba, Facultad de Matemática, Astronomía, Física y Computación.
- Eyrolles, N. (2017). Obfuscation with Mixed Boolean-Arithmetic Expressions: Reconstruction, Analysis and Simplification Tools (Doctoral thesis). Paris-Saclay University (COmUE).


# Language definition

### `given` section
The `given` section takes a pattern from JASM, which matches sintactically. This is intended to find the addresses where symbolic execution will be focused. It also defines variables that will be used in the rest of the code, i.e., variables mentioned in given can be used in all subsequent sections.

Example:

```yml
given:
  pattern
    - $or:
      - add
      - mov
    - cmp
```

### `where`
The `where` section will reduce the number of findings by setting some constraints over the symbolic variables.
For example, here are the restrictions on the data flow `$a -> $b`. And some declaration of variables such as `a1 := argument(ptrace-call, 1)`

```yml
    where:
    - $dx := *ptr
    - $y -> $dx
```

### `such-that` section
The `such-that` section will set solver goals. For example,

```yml
such-that:
  - $y = $z
```

Here the predicate `y = z` is forced to be True, so the possible values of both variables will be constrained to satisfy that condition.

(TODO) After the constraints are set, there is a check for satisfability.

### then section
In this section, a predicate is evaluated with all the resulting possible values.

For example,
```
then:
  - $dx == 0xFA1E0FF3
```

### report section
If the condition in the then section is met, the message in the report section will be printed.

Example:
```yml
report: "Dangr!"
```
