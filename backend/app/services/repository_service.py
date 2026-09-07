import shutil
import subprocess
import tempfile
from pathlib import Path


class RepositoryService:
    ALLOWED_EXTENSIONS = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs",
        ".c", ".cpp", ".h", ".hpp", ".php", ".rb", ".swift", ".kt",
        ".kts", ".cs",
    }

    IGNORED_DIRECTORIES = {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__",
        "dist",
        "build",
        "target",
        "tests",
        "test",
        "docs",
    }

    MAX_FILE_SIZE = 100_000
    CHUNK_SIZE = 50_000

    def clone_repository(self, repository_url: str) -> Path:
        print("REPOSITORY URL RECEIVED:", repository_url)
        
        temp_directory = Path(
            tempfile.mkdtemp(prefix="shadowcode_")
        )
    
    

        try:
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    repository_url,
                    str(temp_directory),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            return temp_directory

        except subprocess.CalledProcessError as error:
            shutil.rmtree(
                temp_directory,
                ignore_errors=True,
            )

            raise ValueError(
                f"Unable to clone repository: "
                f"{error.stderr.strip()}"
            )

    def collect_source_files(
        self,
        repository_path: Path,
    ) -> list[Path]:

        source_files = []

        for path in repository_path.rglob("*"):

            if not path.is_file():
                continue

            if any(
                directory in self.IGNORED_DIRECTORIES
                for directory in path.parts
            ):
                continue

            if path.suffix.lower() in self.ALLOWED_EXTENSIONS:
                source_files.append(path)

        return source_files

    def read_file(self, file_path: Path) -> str:
        try:
            if file_path.stat().st_size > self.MAX_FILE_SIZE:
                raise ValueError(
                    f"File {file_path} is too large to analyze"
                )

            return file_path.read_text(
                encoding="utf-8",
                errors="ignore",
            )

        except OSError as error:
            raise ValueError(
                f"Unable to read file {file_path}: {error}"
            )

    def read_file_chunks(self, file_path: Path) -> list[str]:
        try:
            content = file_path.read_text(
                encoding="utf-8",
                errors="ignore",
            )

            if len(content) <= self.MAX_FILE_SIZE:
                return [content]

            return [
                content[i:i + self.CHUNK_SIZE]
                for i in range(
                    0,
                    len(content),
                    self.CHUNK_SIZE,
                )
            ]

        except OSError as error:
            raise ValueError(
                f"Unable to read file {file_path}: {error}"
            )

    def cleanup(self, repository_path: Path) -> None:
        shutil.rmtree(
            repository_path,
            ignore_errors=True,
        )