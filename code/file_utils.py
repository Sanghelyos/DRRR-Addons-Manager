from pathlib import Path
from tkinter import messagebox
import shutil
from datetime import datetime
import sys
import pefile
from game import Game
from typing import List, Tuple, Optional


def write_autoload(current_game: Game, active_addons: List[str]) -> None:
    """Write active addons to the game's config file."""
    with current_game.config_path.open("w", encoding="utf-8") as f:
        for addon in active_addons:
            f.write(f"addfile addons\\{addon}\n")


def delete_file(path: Path) -> None:
    path.unlink()


def update_enabled_file(addon: str, addons_enabled_list_path: Path) -> None:
    """Updates enabled addons list."""
    with addons_enabled_list_path.open("r", encoding="utf-8") as f:
        lines = [line.strip() for line in f]

    if addon in lines:
        # Remove it
        lines = [line for line in lines if line != addon]
    else:
        # Add it
        lines.append(addon)

    # Save back
    with addons_enabled_list_path.open("w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def backup_save(current_game: Game, save_backup_dir: Path) -> None:
    """Backup all save files to a timestamped folder."""
    now = datetime.now()
    backup_path = save_backup_dir / now.strftime("%Y-%m-%d %H-%M-%S")
    backup_path.mkdir(parents=True, exist_ok=True)

    for save_file in current_game.save_files:
        src = current_game.dir / save_file
        dst = backup_path / save_file
        try:
            shutil.copy(src, dst)
        except Exception:
            messagebox.showerror("Error", f"Couldn't backup {save_file}!")
            return

    messagebox.showinfo("Info", "Backup created successfully!")


def resource_path(relative_path: Path) -> Path:
    """Return absolute path to resource, works with PyInstaller."""
    try:
        base_path = Path(sys._MEIPASS)
    except AttributeError:
        base_path = Path(__file__).resolve().parent.parent
    return base_path / relative_path


def get_file_version(path: Path) -> Optional[str]:
    """Extract the FileVersion from a Windows executable."""
    pe = pefile.PE(path)
    for fileinfo in getattr(pe, "FileInfo", []) or []:
        items = fileinfo if isinstance(fileinfo, list) else [fileinfo]
        for fi in items:
            if getattr(fi, "Key", None) == b"StringFileInfo":
                for st in getattr(fi, "StringTable", []) or []:
                    ver = st.entries.get(b"FileVersion")
                    if ver:
                        return ver.decode(errors="ignore")
    return None


def scan_addons(
    addons_dir: Path, addons_enabled_file_path: Path
) -> Tuple[List[str], List[str], List[str]]:
    """Return active and inactive addons."""
    addons = (
        [
            f.name
            for f in addons_dir.iterdir()
            if f.is_file() and not f.name.endswith(".txt")
        ]
        if addons_dir.exists()
        else []
    )
    with addons_enabled_file_path.open("r", encoding="utf-8") as f:
        active_list = [line.strip() for line in f]

    all_addons = set(addons)
    active_addons = set(active_list)

    active = list(all_addons & active_addons)
    inactive = list(all_addons - active_addons)

    return active, inactive
