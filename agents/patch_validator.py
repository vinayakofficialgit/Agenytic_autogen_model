"""
Patch Validator
Ensures patch is safe before commit.
"""

import subprocess

class PatchValidator:

    def compile_check(self):
        proc = subprocess.run(["mvn", "-q", "clean", "package"])
        return proc.returncode == 0

    def test_check(self):
        proc = subprocess.run(["mvn", "-q", "test"])
        return proc.returncode == 0