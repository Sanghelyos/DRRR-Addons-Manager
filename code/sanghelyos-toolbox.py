import tkinter as tk
from tkinter import messagebox, ttk, font
from tkinter.scrolledtext import ScrolledText
from functools import partial
import sys
from pathlib import Path

from game import Game
from file_utils import *
from github_utils import get_latest_github_release, open_latest_build_webpage

APP_VERSION = "1.3"

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
        None,
        "KartKrewDev",
        "RingRacers",
    ),
    "srb2kart": Game(
        "srb2kart.exe",
        "kartexec.cfg",
        "Sonic Robo Blast 2 Kart",
        ["kartdata.dat"],
        BASE_DIR,
        None,
        "STJr",
        "Kart-Public",
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

    CURRENT_GAME.version = get_file_version(CURRENT_GAME.exe_path)

    if not CURRENT_GAME.version:
        messagebox.showerror(
            "Error", f"Couldn't get {CURRENT_GAME.title} version number"
        )
        exit(1)


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


def check_for_update() -> None:
    remote_version = get_latest_github_release(
        CURRENT_GAME.github_user_name, CURRENT_GAME.github_repo_name
    ).replace("v", "")

    if CURRENT_GAME.version == remote_version:
        messagebox.showinfo("Info", f"You are up to date!")

        return
    elif CURRENT_GAME.version > remote_version:
        answer = messagebox.askyesno(
            "What the fuck?",
            f"You have a higher version ({CURRENT_GAME.version}) than the official repo version ({remote_version}). Please check that you are using an official build.\n\nDo you want to visit the official latest build page?",
        )
        if answer:
            open_latest_build_webpage(
                CURRENT_GAME.github_user_name, CURRENT_GAME.github_repo_name
            )

        return

    answer = messagebox.askyesno(
        "Update Available!",
        f"You are missing updates. Last version is {remote_version}\n\nDo you want to visit the official latest build page?",
    )
    if answer:
        open_latest_build_webpage(
            CURRENT_GAME.github_user_name, CURRENT_GAME.github_repo_name
        )


# ------------------ Main ------------------


def main() -> None:
    global root, listbox_active, listbox_inactive

    check_environment()

    root = tk.Tk()
    root.title(f"Sanghelyos's {CURRENT_GAME.title} Toolbox")

    icon_path = resource_path(ICON_FILE)
    if icon_path.exists():
        try:
            root.iconbitmap(str(icon_path))
        except Exception:
            messagebox.showwarning("Warning", "Can't load custom icon.")

    main_frame = tk.Frame(root)
    main_frame.pack(fill="both", expand=True)

    notebook = ttk.Notebook(main_frame)
    notebook.pack(fill="both", expand=True)

    # Create frames for each tab
    home_tab = ttk.Frame(notebook)
    addons_manager_tab = ttk.Frame(notebook)
    misc_tab = ttk.Frame(notebook)

    # Add frames to the notebook as tabs
    notebook.add(home_tab, text="Home")
    notebook.add(addons_manager_tab, text="Addons Manager")
    notebook.add(misc_tab, text="Miscellaneous")

    # ------------------- Home Tab ------------------- #

    text = ScrolledText(home_tab, wrap="word", width=50, height=15)
    text.pack(fill="both", expand=True, padx=10, pady=10)

    # Insert texts
    text.insert("1.0", f"Welcome to Sanghelyos's {CURRENT_GAME.title} Toolbox!\n\n")
    text.insert(
        "end",
        "This tool allows you to enable or disable addons for auto-loading.\n/!\ Disabled addons won't be able to be loaded from in-game loader.\n\n",
    )
    text.insert(
        "end",
        "It also allows two other features:\n - Making backup of save files\n - Checking for game updates from official GitHub",
    )

    # Add tags for title formatting
    text.tag_add("title", "1.0", "1.end")
    text.tag_config("title", font=("Impact", 16, "bold"), foreground="red")

    default_font = font.nametofont("TkDefaultFont")
    text.tag_add("warning_1", "4.0", "4.3")
    text.tag_config(
        "warning_1",
        font=(default_font.actual("family"), default_font.actual("size"), "bold"),
        foreground="red",
    )

    text.config(state="disabled")

    # ------------------- Addons Manager Tab ------------------- #

    tk.Button(
        addons_manager_tab,
        text="Enable/Update autoloader",
        command=update_config_wrapper,
    ).pack(pady=15)
    tk.Button(
        addons_manager_tab,
        text="Disable autoloader",
        command=partial(disable_mods, CURRENT_GAME),
    ).pack(pady=5)

    lists_frame = tk.Frame(addons_manager_tab)
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

    tk.Button(addons_manager_tab, text="Refresh list", command=refresh_lists).pack(
        pady=5
    )

    # ------------------- Miscellaneous Tab ------------------- #

    misc_grid_frame = tk.Frame(misc_tab)
    misc_grid_frame.pack(pady=15)

    tk.Button(
        misc_grid_frame,
        text="Backup Save",
        command=partial(backup_save, CURRENT_GAME, SAVE_BACKUPS_DIR),
    ).grid(row=0, column=0, padx=5)

    tk.Button(misc_grid_frame, text="Check for update", command=check_for_update).grid(
        row=0, column=1, padx=5
    )

    # ------------------- Bottom frame ------------------- #

    bottom_frame = tk.Frame(main_frame, relief="raised", bd=1)
    bottom_frame.pack(fill="x", side="bottom")
    tk.Label(bottom_frame, text=f"Toolbox version: {APP_VERSION}").pack()
    tk.Label(bottom_frame, text=f"Game version: {CURRENT_GAME.version}").pack()

    refresh_lists()
    root.mainloop()


if __name__ == "__main__":
    main()
