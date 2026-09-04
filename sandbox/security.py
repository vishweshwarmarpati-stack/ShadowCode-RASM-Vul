import re


class SandboxSecurity:

    ALLOWED_COMMANDS = {
        "python",
        "python3",
        "pytest",
        "npm",
        "node",
        "mvn",
        "gradle",
        "go",
        "cargo",
        "rustc",
    }

    FORBIDDEN_OPERATORS = {
        "&&",
        "||",
        ";",
        "|",
        ">",
        ">>",
        "<",
        "$(",
        "`",
    }

    def __init__(
        self,
        memory_limit: str = "512m",
        cpu_limit: float = 1.0,
        network_disabled: bool = True,
        pids_limit: int = 100,
        timeout: int = 30,
    ):
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.network_disabled = network_disabled
        self.pids_limit = pids_limit
        self.timeout = timeout

    def get_limits(self):
        return {
            "memory_limit": self.memory_limit,
            "cpu_limit": self.cpu_limit,
            "network_disabled": self.network_disabled,
            "pids_limit": self.pids_limit,
            "timeout": self.timeout,
        }

    def validate(self):
        if self.cpu_limit <= 0:
            raise ValueError(
                "CPU limit must be greater than 0"
            )

        if self.pids_limit <= 0:
            raise ValueError(
                "PID limit must be greater than 0"
            )

        if self.timeout <= 0:
            raise ValueError(
                "Timeout must be greater than 0"
            )

        if not self.memory_limit:
            raise ValueError(
                "Memory limit cannot be empty"
            )

        return True

    def validate_command(self, command: str):
        if not command or not command.strip():
            raise ValueError(
                "Command cannot be empty"
            )

        command = command.strip()

        # Block shell command chaining and redirection
        for operator in self.FORBIDDEN_OPERATORS:
            if operator in command:
                raise PermissionError(
                    f"Forbidden shell operator detected: {operator}"
                )

        # Get the first executable
        executable = command.split()[0]

        # Normalize paths
        executable = executable.replace("\\", "/")
        executable = executable.split("/")[-1]

        if executable not in self.ALLOWED_COMMANDS:
            raise PermissionError(
                f"Command not allowed in sandbox: {executable}"
            )

        return True


if __name__ == "__main__":

    security = SandboxSecurity()

    print("===== SHADOWCODE SECURITY =====")

    security.validate()

    limits = security.get_limits()

    for key, value in limits.items():
        print(f"{key}: {value}")

    print("\n===== COMMAND POLICY =====")

    # Safe command
    security.validate_command("pytest -q")
    print("[+] pytest command allowed")

    # Dangerous executable
    try:
        security.validate_command(
            "curl example.com"
        )
    except PermissionError as e:
        print(
            f"[+] Dangerous command blocked: {e}"
        )

    # Command chaining
    try:
        security.validate_command(
            "pytest -q && curl example.com"
        )
    except PermissionError as e:
        print(
            f"[+] Command chaining blocked: {e}"
        )

    # Shell pipe
    try:
        security.validate_command(
            "pytest -q | curl example.com"
        )
    except PermissionError as e:
        print(
            f"[+] Shell pipe blocked: {e}"
        )

    print("\n[+] Security configuration valid")