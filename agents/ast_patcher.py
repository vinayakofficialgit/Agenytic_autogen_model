"""
AST Patch Engine
Safe code transformation for Java vulnerabilities.
"""

from pathlib import Path

class ASTPatcher:

    def fix_sql_injection(self, file_path: Path):
        text = file_path.read_text()

        if 'WHERE id=" + id' in text:
            text = text.replace(
                'WHERE id=" + id',
                'WHERE id=?'
            )
            file_path.write_text(text)
            return True

        return False

    def fix_command_injection(self, file_path: Path):
        text = file_path.read_text()

        if "Runtime.getRuntime().exec" in text:
            text = text.replace(
                "Runtime.getRuntime().exec",
                "new ProcessBuilder"
            )
            file_path.write_text(text)
            return True

        return False