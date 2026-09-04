from importlib import import_module

try:
    docker = import_module("docker")
    DockerException = docker.errors.DockerException
except ModuleNotFoundError:
    docker = None

    class DockerException(Exception):
        pass

from pathlib import Path

from sandbox.security import SandboxSecurity


class DockerSandbox:

    def __init__(
        self,
        security: SandboxSecurity | None = None,
    ):
        self.security = security or SandboxSecurity()

        try:
            self.security.validate()

            if docker is None:
                raise RuntimeError(
                    "Docker SDK is not installed. "
                    "Install it with: pip install docker"
                )

            self.client = docker.from_env()
            self.client.ping()

            print("[+] Connected to Docker")

        except DockerException as e:
            raise RuntimeError(
                f"Could not connect to Docker: {e}"
            ) from e

    def run(
        self,
        image: str,
        command: str,
        workspace: str | None = None,
    ):
        container = None
        limits = self.security.get_limits()

        try:
            # Security validation
            self.security.validate_command(command)

            print("[+] Starting secure sandbox")
            print(f"[+] Image: {image}")
            print(f"[+] Command: {command}")
            print(
                f"[+] Memory limit: "
                f"{limits['memory_limit']}"
            )
            print(
                f"[+] CPU limit: "
                f"{limits['cpu_limit']}"
            )
            print(
                f"[+] Network disabled: "
                f"{limits['network_disabled']}"
            )
            print(
                f"[+] PID limit: "
                f"{limits['pids_limit']}"
            )
            print(
                f"[+] Timeout: "
                f"{limits['timeout']} seconds"
            )

            volumes = None
            working_dir = None

            if workspace:
                workspace_path = Path(
                    workspace
                ).resolve()

                if not workspace_path.exists():
                    raise FileNotFoundError(
                        f"Workspace does not exist: "
                        f"{workspace_path}"
                    )

                if not workspace_path.is_dir():
                    raise NotADirectoryError(
                        f"Workspace is not a directory: "
                        f"{workspace_path}"
                    )

                print(
                    f"[+] Host workspace: "
                    f"{workspace_path}"
                )

                volumes = {
                    str(workspace_path): {
                        "bind": "/workspace",
                        "mode": "rw",
                    }
                }

                working_dir = "/workspace"

            # Start container
            container = self.client.containers.run(
                image=image,
                command=[
                    "/bin/sh",
                    "-c",
                    command,
                ],
                detach=True,
                remove=False,
                mem_limit=limits["memory_limit"],
                nano_cpus=int(
                    limits["cpu_limit"]
                    * 1_000_000_000
                ),
                network_disabled=(
                    limits["network_disabled"]
                ),
                pids_limit=limits["pids_limit"],
                user="nobody",
                volumes=volumes,
                working_dir=working_dir,
            )

            print(
                f"[+] Container started: "
                f"{container.short_id}"
            )

            # Wait for completion
            try:
                result = container.wait(
                    timeout=limits["timeout"]
                )

            except Exception as e:

                # Docker SDK raises an exception
                # when the wait exceeds the timeout.
                print(
                    f"[!] Container execution "
                    f"timed out after "
                    f"{limits['timeout']} seconds"
                )

                try:
                    container.kill()
                except DockerException:
                    pass

                return {
                    "exit_code": -1,
                    "status": "timeout",
                    "logs": (
                        f"Execution timed out after "
                        f"{limits['timeout']} seconds: "
                        f"{e}"
                    ),
                }

            # Collect logs
            logs = container.logs().decode(
                "utf-8",
                errors="replace",
            )

            exit_code = result["StatusCode"]

            print("[+] Container finished")

            return {
                "exit_code": exit_code,
                "status": (
                    "passed"
                    if exit_code == 0
                    else "failed"
                ),
                "logs": logs,
            }

        except DockerException as e:

            print(
                f"[!] Docker execution error: {e}"
            )

            return {
                "exit_code": -2,
                "status": "docker_error",
                "logs": str(e),
            }

        finally:

            if container is not None:

                try:
                    container.remove(
                        force=True
                    )

                    print(
                        "[+] Container cleaned up"
                    )

                except DockerException as e:

                    print(
                        f"[!] Cleanup failed: {e}"
                    )


if __name__ == "__main__":

    security = SandboxSecurity(
        memory_limit="512m",
        cpu_limit=1.0,
        network_disabled=True,
        pids_limit=100,
        timeout=30,
    )

    sandbox = DockerSandbox(
        security=security
    )

    result = sandbox.run(
        image="python:3.12-slim",
        command="python --version",
    )

    print("\n===== RESULT =====")

    print(
        f"Exit code: "
        f"{result['exit_code']}"
    )

    print(
        f"Status: "
        f"{result['status']}"
    )

    print(
        f"Output:\n"
        f"{result['logs'].strip()}"
    )