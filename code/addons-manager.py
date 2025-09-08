import os
import shutil
import tkinter as tk
from tkinter import messagebox
import sys
from pathlib import Path
from game import Game
import json

APP_VERSION = "1.2"

# MAKE USE OF DEV ENVIRONMENT
DEV_MODE = True

# Game directory
BASE_DIR = Path(__file__).resolve().parent
GAME_DIR = BASE_DIR / "../game_dev_directory" if DEV_MODE else BASE_DIR

GAMES = {
    "ringracers": Game(
        "ringracers.exe", "ringexec.cfg", "Dr. Robotnik's Ring Racers", GAME_DIR
    ),
    "srb2kart": Game(
        "srb2kart.exe", "kartexec.cfg", "Sonic Robo Blast 2 Kart", GAME_DIR
    ),
}

ADDONS_DIR = GAME_DIR / "addons"
DISABLED_DIR = GAME_DIR / "addons_disabled"
ICON_FILE = BASE_DIR / "../assets/icon.ico" if DEV_MODE else GAME_DIR / "assets/icon.ico"

CURRENT_GAME = None


def check_environment() -> None:
    global CURRENT_GAME
    if GAMES["srb2kart"].exe_path.exists():
        CURRENT_GAME = GAMES["srb2kart"]
    elif GAMES["ringracers"].exe_path.exists():
        CURRENT_GAME = GAMES["ringracers"]
    else:
        messagebox.showerror(
            "Error",
            f'{GAMES["srb2kart"].exe_name} or {GAMES["ringracers"].exe_name} can\'t be found. Please place the mod manager executable in the root directory of one of these games.',
        )
        sys.exit(1)

    if not ADDONS_DIR.exists():
        ADDONS_DIR.mkdir(parents=True, exist_ok=True)
    if not DISABLED_DIR.exists():
        DISABLED_DIR.mkdir(parents=True, exist_ok=True)


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
        base_path = BASE_DIR
    
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

    btn_scan = tk.Button(frame, text="Enable/Update autoloader", command=update_config)
    btn_scan.pack(pady=5)

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

    refresh_lists()

    root.mainloop()


if __name__ == "__main__":
    main()
