from pathlib import Path
from tkinter import messagebox
import shutil
from datetime import datetime
import sys
import pefile
from game import Game
from typing import List, Tuple, Optional


def write_config(current_game: Game, active_addons: List[str]) -> None:
    """Write active addons to the game's config file."""
    with current_game.config_path.open("w", encoding="utf-8") as f:
        for addon in active_addons:
            f.write(f"addfile addons\\{addon}\n")


def disable_mods(current_game: Game) -> None:
    """Delete the game's config file to disable autoload."""
    if current_game.config_path.exists():
        current_game.config_path.unlink()
        messagebox.showinfo("Info", "Addons autoload disabled.")
    else:
        messagebox.showinfo("Info", f"No {current_game.config_name} file to delete.")


def move_addon(addon: str, source: Path, dest: Path) -> None:
    """Move an addon from source folder to destination folder."""
    src_path = source / addon
    dest_path = dest / addon
    if src_path.exists():
        shutil.move(str(src_path), str(dest_path))
    else:
        messagebox.showerror("Error", f"Cannot move {addon}!")


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
    addons_dir: Path, disabled_dir: Path
) -> Tuple[List[str], List[str], List[str]]:
    """Return active, inactive addons, and list of duplicates."""
    active = (
        [f.name for f in addons_dir.iterdir() if f.is_file()]
        if addons_dir.exists()
        else []
    )
    inactive = (
        [f.name for f in disabled_dir.iterdir() if f.is_file()]
        if disabled_dir.exists()
        else []
    )
    duplicates = list(set(active) & set(inactive))
    return active, inactive, duplicates
