from pathlib import Path
import subprocess


class RepositoryManager:
    def __init__(self, workspace_root: str = ".sandbox_workspaces"):
        self.workspace_root = Path(workspace_root)
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def clone(self, repo_url: str, repo_name: str = "repository"):
        target = self.workspace_root / repo_name

        if target.exists():
            raise FileExistsError(
                f"Repository workspace already exists: {target}"
            )

        print(f"[+] Cloning repository")
        print(f"[+] URL: {repo_url}")
        print(f"[+] Destination: {target}")

        result = subprocess.run(
            ["git", "clone", repo_url, str(target)],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Git clone failed:\n{result.stderr}"
            )

        print("[+] Repository cloned successfully")

        return str(target)


if __name__ == "__main__":
    manager = RepositoryManager()

    repo_url = "https://github.com/octocat/Hello-World.git"

    repo_path = manager.clone(
        repo_url=repo_url,
        repo_name="test-repository",
    )

    print("\n===== CLONE RESULT =====")
    print(f"Repository path: {repo_path}")