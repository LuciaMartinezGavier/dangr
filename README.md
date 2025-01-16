# ⚠️ Dangr: Declarative language for finding vulnerabilities and Indicators of Compromise with symbolic execution

## Abstract
In a context where cybersecurity threats are becoming increasingly sophisticated, detecting vulnerabilities and indicators of compromise is a critical challenge. Current tools for identifying insecure software, which rely on fingerprinting analysis, are often insufficient when faced with unknown binaries, obfuscations and compiler optimizations. This highlights the need for more adaptive approaches that incorporate semantic analysis to identify behavioral patterns.

This work introduces Dangr, a declarative language designed for detecting vulnerabilities and suspicious behaviors in binaries, based on symbolic execution. Dangr enables the definition of rules that combine syntactic and semantic properties, facilitating the identification of malicious behaviors even in complex scenarios. The system includes two main components: a compiler that translates Dangr rules into Python programs and a runtime library that implements analysis primitives using the angr framework.

As part of the validation process, scenarios such as the real-world case of debugging evasion in the attack on liblzma, a component of the XZ backdoor, were studied. The results highlight that Dangr enables the implementation of more precise automated detections by integrating semantic analysis, making it easier to identify complex patterns in binaries.

---

## Repository Overview

This repository contains the implementation of **Dangr**, a declarative language for detecting vulnerabilities in binaries through symbolic execution. The project is divided into two main components:

1. **Compiler (`dangr_c`)**  
   The compiler translates Dangr rules written in a declarative syntax into Python programs. These generated programs leverage `dangr_rt` for symbolic execution and semantic analysis.

2. **Runtime Library (`dangr_rt`)**  
   The runtime library provides the foundational analysis primitives used by the compiled programs. It includes modules for simulation, dependency analysis, expression handling, and more, built on top of the `angr` framework.

---

## Key Features

- **Declarative Rules:** Write concise and expressive rules to detect vulnerabilities and indicators of compromise.
- **Symbolic Execution:** Analyze binaries at a semantic level, bypassing challenges like obfuscation and optimization.
- **Custom Analysis Primitives:** Extendable runtime library for advanced analysis needs.
- **Real-World Applications:** Validated against scenarios such as debugging evasion in the XZ backdoor.

---

## Installation

This project uses [Poetry](https://python-poetry.org/) for dependency management. To install the project and its dependencies:

### Clone the repository:
```bash
git clone https://github.com/LuciaMartinezGavier/dangr.git
cd dangr
```

### Install dependencies:
```bash
cd dangr_c
poetry shell
poetry install
```

### Define Rules
- Write your rules in the Dangr declarative syntax (e.g., .yaml files).
- Find the syntax in [dangr_c/README.md](dangr_c/README.md).

### Compile Rules
- Use the compiler `dangr_c` to generate Python code:
```bash
python dangr_c/dangr_c/main.py <rule.yaml>
```

### Run Analysis
- Execute the generated Python script to analyze the target binary:
- use `python <rule.py> --help` to learn more about the possible configurations

```bash
python <rule.py> --binary <target_binary>
```

## Testing
To run the test suite, use the following command in the respective directories:

```bash
pytest
```
