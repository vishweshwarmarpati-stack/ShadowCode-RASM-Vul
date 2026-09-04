from pathlib import Path

from sandbox.container import DockerSandbox
from sandbox.security import SandboxSecurity


class TestRunner:

    def __init__(
        self,
        security: SandboxSecurity | None = None,
    ):
        self.security = security or SandboxSecurity()

        self.sandbox = DockerSandbox(
            security=self.security
        )

    def run_tests(
        self,
        image: str,
        test_command: str,
        workspace: str,
    ):
        print("[+] TestRunner: starting tests")
        print(f"[+] Docker image: {image}")
        print(f"[+] Test command: {test_command}")
        print(f"[+] Workspace: {workspace}")

        calculator = Path(workspace) / "calculator.py"

        print("\n===== HOST FILE BEFORE DOCKER =====")

        if calculator.exists():
            print(calculator.read_text())
        else:
            print("calculator.py NOT FOUND")

        print("===================================")

        result = self.sandbox.run(
            image=image,
            command=test_command,
            workspace=workspace,
        )

        passed = result["exit_code"] == 0

        print("\n===== DOCKER TEST OUTPUT =====")
        print(result["logs"])
        print("==============================")

        return {
            "passed": passed,
            "exit_code": result["exit_code"],
            "logs": result["logs"],
        }


if __name__ == "__main__":

    security = SandboxSecurity(
        memory_limit="512m",
        cpu_limit=1.0,
        network_disabled=True,
        pids_limit=100,
        timeout=30,
    )

    runner = TestRunner(
        security=security
    )

    result = runner.run_tests(
        image="shadowcode-python-test",
        test_command="pytest -q -p no:cacheprovider",
        workspace=".sandbox_workspaces/python-test",
    )

    print("\n===== TEST RESULT =====")
    print(f"Passed: {result['passed']}")
    print(f"Exit code: {result['exit_code']}")
    print(
        f"Logs:\n"
        f"{result['logs'].strip()}"
    )