import asyncio
import uuid
from pathlib import Path


class SandboxService:

    # ========================================================
    # SANDBOX LIMITS
    # ========================================================

    TIMEOUT_SECONDS = 10

    MEMORY_LIMIT = "128m"

    CPU_LIMIT = "0.5"

    PIDS_LIMIT = "64"


    # ========================================================
    # VERIFY PYTHON CODE
    # ========================================================

    async def verify_python_code(
        self,
        code: str,
    ) -> dict:

        sandbox_id = (
            f"shadowcode-sandbox-"
            f"{uuid.uuid4().hex[:12]}"
        )

        sandbox_dir = (
            Path("/tmp") / sandbox_id
        )

        sandbox_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        code_file = (
            sandbox_dir / "main.py"
        )

        try:

            # ------------------------------------------------
            # Write submitted code
            # ------------------------------------------------

            code_file.write_text(
                code,
                encoding="utf-8",
            )

            # ------------------------------------------------
            # Docker sandbox
            # ------------------------------------------------

            command = [

                "docker",

                "run",

                "--rm",

                # --------------------------------------------
                # Network isolation
                # --------------------------------------------

                "--network",
                "none",

                # --------------------------------------------
                # Memory limitation
                # --------------------------------------------

                "--memory",
                self.MEMORY_LIMIT,

                # --------------------------------------------
                # CPU limitation
                # --------------------------------------------

                "--cpus",
                self.CPU_LIMIT,

                # --------------------------------------------
                # Process limitation
                # --------------------------------------------

                "--pids-limit",
                self.PIDS_LIMIT,

                # --------------------------------------------
                # Read-only root filesystem
                # --------------------------------------------

                "--read-only",

                # --------------------------------------------
                # Temporary writable /tmp
                # --------------------------------------------

                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=32m",

                # --------------------------------------------
                # Drop Linux capabilities
                # --------------------------------------------

                "--cap-drop",
                "ALL",

                # --------------------------------------------
                # Prevent privilege escalation
                # --------------------------------------------

                "--security-opt",
                "no-new-privileges",

                # --------------------------------------------
                # Run as non-root user
                # --------------------------------------------

                "--user",
                "65534:65534",

                # --------------------------------------------
                # Mount ONLY the submitted source file
                # --------------------------------------------

                "-v",
                (
                    f"{code_file}"
                    f":/sandbox/main.py:ro"
                ),

                # --------------------------------------------
                # Python image
                # --------------------------------------------

                "python:3.12-alpine",

                # --------------------------------------------
                # Execute code
                # --------------------------------------------

                "python",

                "/sandbox/main.py",
            ]

            # ------------------------------------------------
            # Start Docker process
            # ------------------------------------------------

            process = (
                await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            )

            # ------------------------------------------------
            # Wait with timeout
            # ------------------------------------------------

            try:

                stdout, stderr = (
                    await asyncio.wait_for(
                        process.communicate(),
                        timeout=self.TIMEOUT_SECONDS,
                    )
                )

            except asyncio.TimeoutError:

                # Stop Docker command
                process.kill()

                try:

                    await process.wait()

                except Exception:

                    pass

                return {
                    "status": "TIMEOUT",
                    "exit_code": None,
                    "output": "",
                    "error": (
                        "Sandbox execution exceeded "
                        f"{self.TIMEOUT_SECONDS} seconds."
                    ),
                    "timed_out": True,
                }

            # ------------------------------------------------
            # Decode output
            # ------------------------------------------------

            output = stdout.decode(
                "utf-8",
                errors="replace",
            )

            error = stderr.decode(
                "utf-8",
                errors="replace",
            )

            # ------------------------------------------------
            # Successful execution
            # ------------------------------------------------

            if process.returncode == 0:

                return {
                    "status": "VERIFIED",
                    "exit_code": 0,
                    "output": output,
                    "error": error,
                    "timed_out": False,
                }

            # ------------------------------------------------
            # Failed execution
            # ------------------------------------------------

            return {
                "status": "FAILED",
                "exit_code": process.returncode,
                "output": output,
                "error": error,
                "timed_out": False,
            }

        # ====================================================
        # Docker not installed
        # ====================================================

        except FileNotFoundError:

            return {
                "status": "ERROR",
                "exit_code": None,
                "output": "",
                "error": (
                    "Docker was not found. "
                    "Make sure Docker Desktop is installed "
                    "and running."
                ),
                "timed_out": False,
            }

        # ====================================================
        # Other errors
        # ====================================================

        except Exception as error:

            return {
                "status": "ERROR",
                "exit_code": None,
                "output": "",
                "error": str(error),
                "timed_out": False,
            }

        # ====================================================
        # Cleanup
        # ====================================================

        finally:

            try:

                code_file.unlink(
                    missing_ok=True
                )

            except OSError:

                pass

            try:

                sandbox_dir.rmdir()

            except OSError:

                pass