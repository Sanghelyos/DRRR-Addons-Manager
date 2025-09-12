from pathlib import Path
from dataclasses import dataclass


@dataclass
class Game:
    exe_name: str
    config_name: str
    title: str
    save_files: list
    game_dir: Path

    @property
    def exe_path(self) -> Path:
        return self.game_dir / self.exe_name

    @property
    def config_path(self) -> Path:
        return self.game_dir / self.config_name
