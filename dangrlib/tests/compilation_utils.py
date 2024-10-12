import os
import subprocess
import glob
from typing import Final
from dataclasses import dataclass

from functools import wraps
ASSEMBLY_DIR: Final = "test_files"


@dataclass(kw_only=True)
class BinaryBasedTestCase:
    asm_filename: str | None = None # Path to the assembly file being tested
    binary: str | None = None       # Path to the binary (automatically generated)


def fullpath(directory, filename):
    return os.path.join(ASSEMBLY_DIR, directory, filename)

def compile_assembly(directory):
    """Decorator that compiles an assembly file, runs the test, and cleans up compiled files."""
    def compile_assembly_decorator(func):
        @wraps(func)
        def wrapper(test_case: BinaryBasedTestCase):
            if test_case.binary is None:
                asm_filepath = fullpath(directory, test_case.asm_filename)
                test_case.binary = asm_filepath.replace(".s", ".o")
                subprocess.run(["as", "--64", "-o", test_case.binary, asm_filepath], check=True)

            return func(test_case)
        return wrapper
    return compile_assembly_decorator

def clean():
    """
    This function runs after all tests are finished and deletes all files that end with '.o'.
    """
    object_files = glob.glob(os.path.join('test_files','*', "*.o"))

    for object_file in object_files:
        if os.path.exists(object_file):
            os.remove(object_file)
