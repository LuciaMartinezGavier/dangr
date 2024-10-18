import os
import subprocess
import glob
from typing import Final
from dataclasses import dataclass
import pytest

ASSEMBLY_DIR: Final = "test_files"

@dataclass(kw_only=True)
class BinaryBasedTestCase:
    files_directory: str
    asm_filename: str | None = None # Path to the assembly file being tested
    binary: str | None = None       # Path to the binary (automatically generated)

def fullpath(directory, filename):
    return os.path.join(ASSEMBLY_DIR, directory, filename)

@pytest.fixture
def test_case(request):
    original_test_case = request.param

    # Perform your setup logic here
    if original_test_case.binary is None:
        asm_filepath = fullpath(original_test_case.files_directory, original_test_case.asm_filename)
        original_test_case.binary = asm_filepath.replace(".s", ".o")
        subprocess.run(["as", "--64", "-o", original_test_case.binary, asm_filepath], check=True)

    return original_test_case


def pytest_sessionfinish(session, exitstatus):
    """
    This function runs after all tests are finished and deletes all files that end with '.o'.
    """
    object_files = glob.glob(os.path.join('test_files','*', "*.o"))

    for object_file in object_files:
        if os.path.exists(object_file):
            os.remove(object_file)
