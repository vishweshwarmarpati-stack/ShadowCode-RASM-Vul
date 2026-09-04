from pathlib import Path
import shutil
import stat


class CleanupManager:

    def __init__(
        self,
        workspace_root: str = ".sandbox_workspaces",
    ):
        self.workspace_root = Path(
            workspace_root
        ).resolve()

        self.workspace_root.mkdir(
            parents=True,
            exist_ok=True,
        )

    def _make_writable(
        self,
        path: Path,
    ):
        """
        Make files writable before deletion.

        Docker containers may create files with
        restrictive permissions.
        """

        if not path.exists():
            return

        if path.is_file():
            try:
                path.chmod(
                    stat.S_IWRITE
                    | stat.S_IREAD
                )
            except OSError:
                pass

        elif path.is_dir():
            try:
                path.chmod(
                    stat.S_IWRITE
                    | stat.S_IREAD
                    | stat.S_IEXEC
                )
            except OSError:
                pass

            try:
                for child in path.iterdir():
                    self._make_writable(child)
            except OSError:
                pass

    def remove_workspace(
        self,
        workspace: str,
    ):
        path = Path(workspace).resolve()

        # Security check:
        # Never delete outside workspace root.
        try:
            path.relative_to(
                self.workspace_root
            )
        except ValueError:
            return {
                "removed": False,
                "message": (
                    "Refusing to delete path "
                    "outside workspace root"
                ),
            }

        # Never delete workspace root itself.
        if path == self.workspace_root:
            return {
                "removed": False,
                "message": (
                    "Refusing to delete "
                    "workspace root"
                ),
            }

        if not path.exists():
            return {
                "removed": True,
                "message": (
                    "Workspace does not exist"
                ),
            }

        if not path.is_dir():
            return {
                "removed": False,
                "message": (
                    "Workspace path is not "
                    "a directory"
                ),
            }

        try:
            # Docker may have created
            # read-only files.
            self._make_writable(path)

            shutil.rmtree(
                path,
                onerror=self._handle_remove_error,
            )

            print(
                f"[+] Workspace removed: {path}"
            )

            return {
                "removed": True,
                "message": (
                    "Workspace removed successfully"
                ),
            }

        except Exception as e:
            return {
                "removed": False,
                "message": str(e),
            }

    def _handle_remove_error(
        self,
        function,
        path,
        exc_info,
    ):
        """
        Retry deletion after changing
        permissions.
        """

        try:
            Path(path).chmod(
                stat.S_IWRITE
                | stat.S_IREAD
                | stat.S_IEXEC
            )

            function(path)

        except Exception:
            raise


if __name__ == "__main__":

    manager = CleanupManager()

    print(
        "===== CLEANUP MANAGER ====="
    )

    result = manager.remove_workspace(
        ".sandbox_workspaces/"
        "does-not-exist"
    )

    print(
        f"Removed: {result['removed']}"
    )

    print(
        f"Message: {result['message']}"
    )

    print(
        "\n[+] Cleanup manager ready"
    )