import runpy
import sys
import inspect
import traceback
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    # Provide a lightweight dummy 'pytest' module if it's not available in
    # the current environment. Tests in Week 1 import pytest but do not
    # rely on pytest runtime features here.
    if 'pytest' not in sys.modules:
        sys.modules['pytest'] = types.SimpleNamespace()

    # Provide a lightweight dummy 'dotenv.load_dotenv' if python-dotenv is
    # not installed. The configuration module calls load_dotenv but tests do
    # not require real .env processing here.
    if 'dotenv' not in sys.modules:
        sys.modules['dotenv'] = types.SimpleNamespace(load_dotenv=lambda *a, **k: None)

    ns = runpy.run_path(str(ROOT / 'tests' / 'test_week1_validation.py'))
    failures = 0
    for name, obj in ns.items():
        if inspect.isfunction(obj) and name.startswith('test_'):
            print('RUN', name)
            try:
                obj()
            except AssertionError as e:
                print('FAIL', name)
                traceback.print_exc()
                failures += 1
            except Exception:
                print('ERROR', name)
                traceback.print_exc()
                failures += 1
            else:
                print('PASS', name)
    if failures:
        print(f"{failures} test(s) failed")
        sys.exit(1)
    print('All tests passed')
except Exception:
    traceback.print_exc()
    sys.exit(2)
