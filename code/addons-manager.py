import shutil
import tkinter as tk
from tkinter import messagebox
import sys
from pathlib import Path
from game import Game
from datetime import datetime

APP_VERSION = "1.2"

# Game directory
if getattr(sys, "frozen", False):
    # PyInstaller exe
    BASE_DIR = Path(sys.executable).parent
else:
    # Python script, usually DEV
    BASE_DIR = Path(__file__).resolve().parent.parent / "game_dev_directory"

GAMES = {
    "ringracers": Game(
        "ringracers.exe", "ringexec.cfg", "Dr. Robotnik's Ring Racers", BASE_DIR
    ),
    "srb2kart": Game(
        "srb2kart.exe", "kartexec.cfg", "Sonic Robo Blast 2 Kart", BASE_DIR
    ),
}

ADDONS_DIR = BASE_DIR / "addons"
DISABLED_DIR = BASE_DIR / "addons_disabled"
SAVE_BACKUPS_DIR = BASE_DIR / "save_backups"
ICON_FILE = Path("assets/icon.ico")

SAVE_FILES = ["ringdata.dat", "ringprofiles.prf"]

CURRENT_GAME = None


def check_environment() -> None:
    global CURRENT_GAME
    for game in GAMES.values():
        if game.exe_path.exists():
            CURRENT_GAME = game
            break

    if CURRENT_GAME is None:
        messagebox.showerror(
            "Error",
            f"Neither ringracers.exe nor srb2kart.exe found. Place the manager in the same folder as the game.",
        )
        sys.exit(1)

    if not ADDONS_DIR.exists():
        ADDONS_DIR.mkdir(parents=True, exist_ok=True)
    if not DISABLED_DIR.exists():
        DISABLED_DIR.mkdir(parents=True, exist_ok=True)
    if not SAVE_BACKUPS_DIR.exists():
        SAVE_BACKUPS_DIR.mkdir(parents=True, exist_ok=True)


def scan_addons() -> None:
    active = (
        set(f.name for f in ADDONS_DIR.iterdir() if f.is_file())
        if ADDONS_DIR.exists()
        else set()
    )
    inactive = (
        set(f.name for f in DISABLED_DIR.iterdir() if f.is_file())
        if DISABLED_DIR.exists()
        else set()
    )

    # Check for duplicates
    duplicates = active & inactive
    if duplicates:
        messagebox.showerror(
            "Error",
            f"Duplicates found in both addons and addons_disabled folders: {', '.join(duplicates)}",
        )

    return list(active), list(inactive)


def write_config(active_addons: list) -> None:
    with CURRENT_GAME.config_path.open("w", encoding="utf-8") as f:
        for addon in active_addons:
            f.write(f"addfile addons\\{addon}\n")


def update_config() -> None:
    active, _ = scan_addons()
    write_config(active)
    messagebox.showinfo("Success", f"Enabled autoload for {len(active)} addons.")


def disable_mods() -> None:
    if Path.exists(CURRENT_GAME.config_path):
        CURRENT_GAME.config_path.unlink()
        messagebox.showinfo("Info", "Addons autoload disabled.")
    else:
        messagebox.showinfo("Info", f"No {CURRENT_GAME.config_name} file to delete.")


def move_addon(addon: str, source: Path, dest: Path) -> None:
    src_path = source / addon
    dest_path = dest / addon
    if src_path.exists():
        shutil.move(str(src_path), str(dest_path))
        refresh_lists()
    else:
        messagebox.showerror("Error", f"Cannot move {addon}!")


def backup_save() -> None:
    current_datetime = datetime.now()
    year = current_datetime.year
    month = current_datetime.month
    day = current_datetime.day
    hour = current_datetime.hour
    minutes = current_datetime.minute
    seconds = current_datetime.second

    backup_path = SAVE_BACKUPS_DIR / f"{year}-{month}-{day} {hour}-{minutes}-{seconds}"

    if not backup_path.exists():
        backup_path.mkdir()

    for save_file in SAVE_FILES:
        try:
            shutil.copy(BASE_DIR / save_file, backup_path / save_file)
        except:
            messagebox.showerror("Error", f"Couldn't make a backup of {save_file}!")
            return

    messagebox.showinfo("Info", "Backup created successfully!")


def refresh_lists() -> None:
    active, inactive = scan_addons()

    listbox_active.delete(0, tk.END)
    listbox_inactive.delete(0, tk.END)

    for a in active:
        listbox_active.insert(tk.END, a)
    for i in inactive:
        listbox_inactive.insert(tk.END, i)


def disable_addon() -> None:
    selection = listbox_active.curselection()
    if selection:
        addon = listbox_active.get(selection[0])
        move_addon(addon, ADDONS_DIR, DISABLED_DIR)


def enable_addon() -> None:
    selection = listbox_inactive.curselection()
    if selection:
        addon = listbox_inactive.get(selection[0])
        move_addon(addon, DISABLED_DIR, ADDONS_DIR)


def resource_path(relative_path: Path) -> Path:
    try:
        base_path = Path(sys._MEIPASS)
    except AttributeError:
        base_path = Path(__file__).resolve().parent.parent

    return base_path / relative_path


def main() -> None:
    global root, listbox_active, listbox_inactive

    check_environment()

    if None == CURRENT_GAME:
        messagebox.showerror("Error", "Couldn't define game environment.")
        sys.exit(1)

    # Define tkinter interface
    root = tk.Tk()
    root.title(f"{CURRENT_GAME.title} Addons Manager v{APP_VERSION}")

    # Define an app icon if possible
    ICON_PATH = resource_path(ICON_FILE)
    print(ICON_PATH)
    if ICON_PATH.exists():
        try:
            root.iconbitmap(str(ICON_PATH))  # Tkinter wants str not Path
        except Exception:
            messagebox.showwarning("Warning", "Can't load custom icon.")

    frame = tk.Frame(root, padx=10, pady=10)
    frame.pack(fill="both", expand=True)

    addons_manager_label = tk.Label(frame, text="Addons Manager")
    addons_manager_label.pack()

    btn_scan = tk.Button(frame, text="Enable/Update autoloader", command=update_config)
    btn_scan.pack(pady=15)

    btn_disable_mods = tk.Button(frame, text="Disable autoloader", command=disable_mods)
    btn_disable_mods.pack(pady=5)

    lists_frame = tk.Frame(frame)
    lists_frame.pack()

    listbox_active = tk.Listbox(lists_frame, width=50, height=15, selectmode=tk.SINGLE)
    listbox_inactive = tk.Listbox(
        lists_frame, width=50, height=15, selectmode=tk.SINGLE
    )

    listbox_active.grid(row=0, column=0, padx=5, pady=5)
    listbox_inactive.grid(row=0, column=2, padx=5, pady=5)

    # Button to move addons from addons or addons_disabled folders
    buttons_frame = tk.Frame(lists_frame)
    buttons_frame.grid(row=0, column=1, padx=5)

    btn_disable = tk.Button(
        buttons_frame, text="→ Disable", command=lambda: disable_addon()
    )
    btn_enable = tk.Button(
        buttons_frame, text="← Enable", command=lambda: enable_addon()
    )

    btn_disable.pack(pady=10)
    btn_enable.pack(pady=10)

    btn_refresh = tk.Button(frame, text="Refresh list", command=refresh_lists)
    btn_refresh.pack(pady=5)

    misc_label = tk.Label(frame, text="Miscellaneous")
    misc_label.pack()

    misc_frame = tk.Frame(frame)
    misc_frame.pack()

    btn_backup_save = tk.Button(misc_frame, text="Backup Save", command=backup_save)
    btn_backup_save.grid(row=0, column=0, pady=15)

    refresh_lists()

    root.mainloop()


if __name__ == "__main__":
    main()
