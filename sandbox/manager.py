from pathlib import Path
import shutil
import tempfile
import subprocess

from sandbox.runtime import RuntimeDetector
from sandbox.patch import PatchManager
from sandbox.tests import TestRunner
from sandbox.security import SandboxSecurity
from sandbox.logs import SandboxLogger
from sandbox.cleanup import CleanupManager


class SandboxManager:

    def __init__(self):
        self.security = SandboxSecurity()
        self.runtime = RuntimeDetector()
        self.patch = PatchManager()
        self.tests = TestRunner(security=self.security)
        self.logger = SandboxLogger()
        self.cleanup = CleanupManager()

    def _create_verification_workspace(
        self,
        repository_path: str,
    ):
        source = Path(repository_path).resolve()

        if not source.exists():
            raise FileNotFoundError(
                f"Repository does not exist: {source}"
            )

        if not source.is_dir():
            raise NotADirectoryError(
                f"Repository is not a directory: {source}"
            )

        verification_root = Path(
            tempfile.mkdtemp(
                prefix="shadowcode-verify-",
                dir=str(self.cleanup.workspace_root),
            )
        )

        verification_path = verification_root / source.name

        # Copy repository including its Git metadata.
        shutil.copytree(
            source,
            verification_path,
            ignore=shutil.ignore_patterns(
                "__pycache__",
                ".pytest_cache",
                ".shadowcode.patch",
            ),
        )

        # Make sure the verification copy is a Git repository.
        git_dir = verification_path / ".git"

        if not git_dir.exists():
            shutil.copytree(
                source / ".git",
                git_dir,
            )

        print(
            f"[+] Created isolated verification workspace: "
            f"{verification_path}"
        )

        return verification_path

    def verify_patch(
        self,
        repository_path: str,
        patch_text: str,
        image: str,
    ):
        self.logger.clear()

        self.logger.log(
            "verification",
            "Starting ShadowCode verification",
        )

        verification_path = None
        test_result = None

        try:
            # -----------------------------------------
            # 1. Runtime detection
            # -----------------------------------------
            self.logger.log(
                "runtime_detection",
                "Detecting project runtime",
            )

            runtime = self.runtime.detect(
                repository_path
            )

            self.logger.log(
                "runtime_detection",
                f"Detected language: {runtime['language']}",
            )

            if runtime["language"] == "unknown":
                self.logger.log(
                    "runtime_detection",
                    "Unknown project runtime",
                    level="ERROR",
                )

                return {
                    "success": False,
                    "stage": "runtime_detection",
                    "error": "Unknown project runtime",
                    "events": self.logger.get_events(),
                }

            # -----------------------------------------
            # 2. Create isolated workspace
            # -----------------------------------------
            self.logger.log(
                "workspace",
                "Creating isolated verification workspace",
            )

            verification_path = (
                self._create_verification_workspace(
                    repository_path
                )
            )

            self.logger.log(
                "workspace",
                f"Workspace created: {verification_path}",
            )

            # -----------------------------------------
            # 3. Validate patch
            # -----------------------------------------
            self.logger.log(
                "patch_validation",
                "Validating generated patch",
            )

            validation = self.patch.validate(
                str(verification_path),
                patch_text,
            )

            if not validation["valid"]:
                self.logger.log(
                    "patch_validation",
                    "Patch validation failed",
                    level="ERROR",
                )

                return {
                    "success": False,
                    "stage": "patch_validation",
                    "error": validation["error"],
                    "events": self.logger.get_events(),
                }

            self.logger.log(
                "patch_validation",
                "Patch validation successful",
            )

            # -----------------------------------------
            # 4. Apply patch
            # -----------------------------------------
            self.logger.log(
                "patch_application",
                "Applying patch to isolated workspace",
            )

            applied = self.patch.apply(
                str(verification_path),
                patch_text,
            )

            if not applied["applied"]:
                self.logger.log(
                    "patch_application",
                    "Patch application failed",
                    level="ERROR",
                )

                return {
                    "success": False,
                    "stage": "patch_application",
                    "error": applied["error"],
                    "events": self.logger.get_events(),
                }

            self.logger.log(
                "patch_application",
                "Patch applied successfully",
            )

            # -----------------------------------------
            # 5. Verify patched file
            # -----------------------------------------
            print("\n===== FILE AFTER PATCH =====")

            patched_file = (
                verification_path / "calculator.py"
            )

            if patched_file.exists():
                print(
                    patched_file.read_text(
                        encoding="utf-8"
                    )
                )
            else:
                print("calculator.py NOT FOUND")

            print("============================")

            # -----------------------------------------
            # 6. Run tests
            # -----------------------------------------
            self.logger.log(
                "tests",
                "Starting tests inside secure sandbox",
            )

            test_result = self.tests.run_tests(
                image=image,
                test_command=runtime["test_command"],
                workspace=str(verification_path),
            )

            if test_result["passed"]:
                self.logger.log(
                    "tests",
                    "All tests passed",
                )
            else:
                self.logger.log(
                    "tests",
                    "Tests failed",
                    level="ERROR",
                )

            # -----------------------------------------
            # 7. Verification result
            # -----------------------------------------
            success = test_result["passed"]

            self.logger.log(
                "verification",
                "Original repository remains untouched",
            )

            if success:
                self.logger.log(
                    "verification",
                    "Patch verified successfully",
                )
            else:
                self.logger.log(
                    "verification",
                    "Patch verification failed",
                    level="ERROR",
                )

            return {
                "success": success,
                "stage": (
                    "verification"
                    if success
                    else "tests"
                ),
                "runtime": runtime,
                "tests": test_result,
                "patch_reverted": True,
                "verification_workspace": str(
                    verification_path
                ),
                "events": self.logger.get_events(),
            }

        finally:
            # -----------------------------------------
            # 8. Cleanup
            # -----------------------------------------
            if verification_path is not None:
                self.logger.log(
                    "cleanup",
                    "Removing isolated verification workspace",
                )

                # Remove Docker-created files first.
                try:
                    subprocess.run(
                        [
                            "docker",
                            "run",
                            "--rm",
                            "--user",
                            "root",
                            "-v",
                            (
                                f"{verification_path.parent.resolve()}"
                                ":/workspace"
                            ),
                            "alpine:latest",
                            "sh",
                            "-c",
                            "rm -rf /workspace/* /workspace/.[!.]* "
                            "/workspace/..?* 2>/dev/null || true",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                except Exception:
                    pass

                cleanup_result = (
                    self.cleanup.remove_workspace(
                        str(verification_path.parent)
                    )
                )

                if cleanup_result["removed"]:
                    self.logger.log(
                        "cleanup",
                        "Isolated workspace removed successfully",
                    )
                else:
                    self.logger.log(
                        "cleanup",
                        cleanup_result["message"],
                        level="ERROR",
                    )

    def cleanup_workspace(
        self,
        repository_path: str,
    ):
        self.logger.log(
            "cleanup",
            "Removing temporary workspace",
        )

        result = self.cleanup.remove_workspace(
            repository_path
        )

        if result["removed"]:
            self.logger.log(
                "cleanup",
                result["message"],
            )
        else:
            self.logger.log(
                "cleanup",
                result["message"],
                level="ERROR",
            )

        return result


if __name__ == "__main__":

    manager = SandboxManager()

    print(
        "[+] SandboxManager initialized"
    )