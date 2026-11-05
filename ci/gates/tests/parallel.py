"""Run a unittest file's tests one process each, in parallel; fail unless every discovered test passed."""
from concurrent.futures import ThreadPoolExecutor
import os
import subprocess
import sys
import unittest


def ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from ids(item)
        else:
            yield item.id().split(".", 1)[1]


def main(test_file, module):
    if len(sys.argv) > 1:
        unittest.main(module=module)
        return
    names = list(ids(unittest.defaultTestLoader.loadTestsFromModule(module)))
    if not names:
        sys.exit(f"FAIL: {test_file}: discovered no tests")
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}

    def run(name):
        done = subprocess.run([sys.executable, "-B", test_file, name], env=env,
                              capture_output=True, text=True, check=False)
        return name, done.returncode, done.stdout + done.stderr

    workers = max(1, os.cpu_count() or 1)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(run, names))
    failed = [(name, out) for name, code, out in results if code != 0]
    for name, out in failed:
        print(f"===== FAIL: {name}\n{out}")
    print(f"Ran {len(results)} tests in {workers} workers: {len(results) - len(failed)} passed, {len(failed)} failed")
    sys.exit(1 if failed or len(results) != len(names) else 0)
