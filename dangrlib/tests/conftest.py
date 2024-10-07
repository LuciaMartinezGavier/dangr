from tests.compilation_utils import clean

def pytest_sessionfinish(session, exitstatus):
    clean()
