from pathlib import Path
from dataclasses import dataclass


@dataclass
class Game:
    exe_name: str
    config_name: str
    title: str
    save_files: list
    dir: Path
    version: None | str
    github_user_name: str
    github_repo_name: str

    @property
    def exe_path(self) -> Path:
        return self.dir / self.exe_name

    @property
    def config_path(self) -> Path:
        return self.dir / self.config_name
