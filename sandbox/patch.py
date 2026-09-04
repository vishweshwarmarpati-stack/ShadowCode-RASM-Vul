from pathlib import Path
import subprocess


class PatchManager:

    def _validate_repository(
        self,
        repository_path: str,
    ):
        repo = Path(repository_path).resolve()

        if not repo.exists():
            raise FileNotFoundError(
                f"Repository does not exist: {repo}"
            )

        if not repo.is_dir():
            raise NotADirectoryError(
                f"Repository is not a directory: {repo}"
            )

        return repo

    def _write_patch(
        self,
        repo: Path,
        patch: str,
    ):
        patch_file = repo / ".shadowcode.patch"

        patch_file.write_text(
            patch,
            encoding="utf-8",
        )

        return patch_file

    def validate(
        self,
        repository_path: str,
        patch: str,
    ):
        repo = self._validate_repository(
            repository_path
        )

        patch_file = self._write_patch(
            repo,
            patch,
        )

        try:
            result = subprocess.run(
                [
                    "git",
                    "apply",
                    "--check",
                    ".shadowcode.patch",
                ],
                cwd=repo,
                capture_output=True,
                text=True,
            )

            return {
                "valid": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
            }

        finally:
            if patch_file.exists():
                patch_file.unlink()

    def apply(
        self,
        repository_path: str,
        patch: str,
    ):
        repo = self._validate_repository(
            repository_path
        )

        patch_file = self._write_patch(
            repo,
            patch,
        )

        try:
            print("[+] Applying patch")

            result = subprocess.run(
                [
                    "git",
                    "apply",
                    "--verbose",
                    ".shadowcode.patch",
                ],
                cwd=repo,
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return {
                    "applied": False,
                    "output": result.stdout,
                    "error": result.stderr,
                }

            # Verify that Git actually changed the working tree.
            verify = subprocess.run(
                [
                    "git",
                    "diff",
                    "--",
                ],
                cwd=repo,
                capture_output=True,
                text=True,
            )

            if not verify.stdout.strip():
                return {
                    "applied": False,
                    "output": result.stdout,
                    "error": (
                        "git apply reported success, "
                        "but no working-tree changes were detected"
                    ),
                }

            print("[+] Patch applied successfully")

            return {
                "applied": True,
                "output": (
                    result.stdout
                    + verify.stdout
                ),
                "error": result.stderr,
            }

        finally:
            if patch_file.exists():
                patch_file.unlink()

    def revert(
        self,
        repository_path: str,
        patch: str,
    ):
        repo = self._validate_repository(
            repository_path
        )

        patch_file = self._write_patch(
            repo,
            patch,
        )

        try:
            print("[+] Reverting patch")

            result = subprocess.run(
                [
                    "git",
                    "apply",
                    "-R",
                    ".shadowcode.patch",
                ],
                cwd=repo,
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return {
                    "reverted": False,
                    "output": result.stdout,
                    "error": result.stderr,
                }

            print("[+] Patch reverted successfully")

            return {
                "reverted": True,
                "output": result.stdout,
                "error": result.stderr,
            }

        finally:
            if patch_file.exists():
                patch_file.unlink()


if __name__ == "__main__":

    repository = ".sandbox_workspaces/python-test"

    patch = """diff --git a/calculator.py b/calculator.py
--- a/calculator.py
+++ b/calculator.py
@@ -1,2 +1,2 @@
 def add(a, b):
-    return a + b
+    return a - b
"""

    manager = PatchManager()

    print("===== PATCH VALIDATION =====")

    validation = manager.validate(
        repository,
        patch,
    )

    print(f"Valid: {validation['valid']}")
    print(f"Output: {validation['output']}")
    print(f"Error: {validation['error']}")

    if not validation["valid"]:
        raise SystemExit(
            "Patch validation failed"
        )

    print("\n===== PATCH APPLICATION =====")

    applied = manager.apply(
        repository,
        patch,
    )

    print(f"Applied: {applied['applied']}")
    print(f"Output:\n{applied['output']}")
    print(f"Error: {applied['error']}")

    calculator = (
        Path(repository) / "calculator.py"
    )

    print("\n===== FILE AFTER APPLY =====")

    if calculator.exists():
        print(
            calculator.read_text(
                encoding="utf-8"
            )
        )

    print("============================")

    print("\n===== PATCH REVERT =====")

    reverted = manager.revert(
        repository,
        patch,
    )

    print(f"Reverted: {reverted['reverted']}")
    print(f"Output: {reverted['output']}")
    print(f"Error: {reverted['error']}")

    print("\n===== FILE AFTER REVERT =====")

    if calculator.exists():
        print(
            calculator.read_text(
                encoding="utf-8"
            )
        )

    print("==============================")