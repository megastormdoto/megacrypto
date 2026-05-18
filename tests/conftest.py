import pytest
import sys
from io import StringIO
from micropki.cli import main as cli_main

def pytest_addoption(parser):
    try:
        parser.addoption(
            "--run-perf", action="store_true", default=False,
            help="Run performance tests (slow, issues 1000 certs)",
        )
    except ValueError:
        pass  # already registered

def pytest_collection_modifyitems(config, items):
    if not config.getoption("--run-perf", default=False):
        skip_perf = pytest.mark.skip(reason="Need --run-perf option to run")
        for item in items:
            if "perf" in item.keywords:
                item.add_marker(skip_perf)

@pytest.fixture(scope="session")
def run_cli():
    """Returns a function to run the CLI in-process and capture output."""
    def _run(*args):
        stdout = StringIO()
        stderr = StringIO()
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        old_argv = sys.argv
        sys.stdout = stdout
        sys.stderr = stderr
        sys.argv = ["micropki"] + [str(a) for a in args]
        
        exit_code = 0
        try:
            exit_code = cli_main() or 0
        except SystemExit as e:
            exit_code = e.code if e.code is not None else 0
        except Exception as e:
            stderr.write(str(e))
            exit_code = 1
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            sys.argv = old_argv
            
        return exit_code, stdout.getvalue(), stderr.getvalue()
    return _run
