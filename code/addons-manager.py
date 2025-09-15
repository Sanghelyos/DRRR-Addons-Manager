import tkinter as tk
from tkinter import messagebox
from functools import partial
import sys
from pathlib import Path

from game import Game
from file_utils import *

APP_VERSION = "1.2.2"

# Directories
BASE_DIR = (
    Path(sys.executable).parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent.parent / "game_dev_directory"
)
ADDONS_DIR = BASE_DIR / "addons"
DISABLED_DIR = BASE_DIR / "addons_disabled"
SAVE_BACKUPS_DIR = BASE_DIR / "save_backups"
ICON_FILE = Path("assets/icon.ico")

GAMES = {
    "ringracers": Game(
        "ringracers.exe",
        "ringexec.cfg",
        "Dr. Robotnik's Ring Racers",
        ["ringdata.dat", "ringprofiles.prf", "srvstats.dat"],
        BASE_DIR,
    ),
    "srb2kart": Game(
        "srb2kart.exe",
        "kartexec.cfg",
        "Sonic Robo Blast 2 Kart",
        ["kartdata.dat"],
        BASE_DIR,
    ),
}

CURRENT_GAME: Game | None = None

# ------------------ Environment ------------------


def check_environment() -> None:
    """Find current game and ensure required folders exist."""
    global CURRENT_GAME
    for game in GAMES.values():
        if game.exe_path.exists():
            CURRENT_GAME = game
            break

    if CURRENT_GAME is None:
        messagebox.showerror(
            "Error",
            "Neither ringracers.exe nor srb2kart.exe found. Place the manager in the game folder.",
        )
        sys.exit(1)

    for folder in [ADDONS_DIR, DISABLED_DIR, SAVE_BACKUPS_DIR]:
        folder.mkdir(parents=True, exist_ok=True)


# ------------------ GUI Logic ------------------


def refresh_lists() -> None:
    active, inactive, duplicates = scan_addons(ADDONS_DIR, DISABLED_DIR)
    if duplicates:
        messagebox.showerror("Error", f"Duplicates found: {', '.join(duplicates)}")

    listbox_active.delete(0, tk.END)
    listbox_inactive.delete(0, tk.END)

    for a in active:
        listbox_active.insert(tk.END, a)
    for i in inactive:
        listbox_inactive.insert(tk.END, i)


def disable_addon() -> None:
    sel = listbox_active.curselection()
    if sel:
        move_addon(listbox_active.get(sel[0]), ADDONS_DIR, DISABLED_DIR)
        refresh_lists()


def enable_addon() -> None:
    sel = listbox_inactive.curselection()
    if sel:
        move_addon(listbox_inactive.get(sel[0]), DISABLED_DIR, ADDONS_DIR)
        refresh_lists()


def update_config_wrapper() -> None:
    active, _, _ = scan_addons(ADDONS_DIR, DISABLED_DIR)
    write_config(CURRENT_GAME, active)
    messagebox.showinfo("Success", f"Enabled autoload for {len(active)} addons.")


# ------------------ Main ------------------


def main() -> None:
    global root, listbox_active, listbox_inactive

    check_environment()

    root = tk.Tk()
    root.title(f"{CURRENT_GAME.title} Addons Manager v{APP_VERSION}")

    icon_path = resource_path(ICON_FILE)
    if icon_path.exists():
        try:
            root.iconbitmap(str(icon_path))
        except Exception:
            messagebox.showwarning("Warning", "Can't load custom icon.")

    frame = tk.Frame(root, padx=10, pady=10)
    frame.pack(fill="both", expand=True)

    tk.Label(frame, text="Addons Manager").pack()

    tk.Button(
        frame, text="Enable/Update autoloader", command=update_config_wrapper
    ).pack(pady=15)
    tk.Button(
        frame, text="Disable autoloader", command=partial(disable_mods, CURRENT_GAME)
    ).pack(pady=5)

    lists_frame = tk.Frame(frame)
    lists_frame.pack()

    listbox_active = tk.Listbox(lists_frame, width=50, height=15, selectmode=tk.SINGLE)
    listbox_inactive = tk.Listbox(
        lists_frame, width=50, height=15, selectmode=tk.SINGLE
    )
    listbox_active.grid(row=0, column=0, padx=5, pady=5)
    listbox_inactive.grid(row=0, column=2, padx=5, pady=5)

    btn_frame = tk.Frame(lists_frame)
    btn_frame.grid(row=0, column=1, padx=5)
    tk.Button(btn_frame, text="→ Disable", command=disable_addon).pack(pady=10)
    tk.Button(btn_frame, text="← Enable", command=enable_addon).pack(pady=10)

    tk.Button(frame, text="Refresh list", command=refresh_lists).pack(pady=5)
    tk.Button(
        frame,
        text="Backup Save",
        command=partial(backup_save, CURRENT_GAME, SAVE_BACKUPS_DIR),
    ).pack(pady=15)

    refresh_lists()
    root.mainloop()


if __name__ == "__main__":
    main()
