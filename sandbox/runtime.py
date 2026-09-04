from pathlib import Path


class RuntimeDetector:

    def detect(self, repository_path: str):
        repo = Path(repository_path)

        if not repo.exists():
            raise FileNotFoundError(
                f"Repository does not exist: {repo}"
            )

        # Python
        if (
            (repo / "pyproject.toml").exists()
            or (repo / "requirements.txt").exists()
            or (repo / "setup.py").exists()
        ):
            return {
                "language": "python",
                "test_command": "pytest -q -p no:cacheprovider",
            }

        # Node.js
        if (repo / "package.json").exists():
            return {
                "language": "node",
                "test_command": "npm test",
            }

        # Java / Maven
        if (repo / "pom.xml").exists():
            return {
                "language": "java",
                "build_tool": "maven",
                "test_command": "mvn test",
            }

        # Java / Gradle
        if (
            (repo / "build.gradle").exists()
            or (repo / "build.gradle.kts").exists()
        ):
            return {
                "language": "java",
                "build_tool": "gradle",
                "test_command": "gradle test",
            }

        # Go
        if (repo / "go.mod").exists():
            return {
                "language": "go",
                "test_command": "go test ./...",
            }

        # Rust
        if (repo / "Cargo.toml").exists():
            return {
                "language": "rust",
                "test_command": "cargo test",
            }

        return {
            "language": "unknown",
            "test_command": None,
        }


if __name__ == "__main__":
    detector = RuntimeDetector()

    result = detector.detect(
        ".sandbox_workspaces/python-test"
    )

    print("===== RUNTIME DETECTION =====")
    print(f"Language: {result['language']}")
    print(f"Test command: {result['test_command']}")