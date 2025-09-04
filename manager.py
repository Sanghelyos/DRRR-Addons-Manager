import os
import shutil
import tkinter as tk
from tkinter import messagebox
import sys

# Files and directories
ADDONS_DIR = "addons"
DISABLED_DIR = "addons_disabled"
CONFIG_FILE = "ringexec.cfg"
GAME_EXE = "ringracers.exe"
ICON_FILE = "icon.ico"


def check_environment():
    if not os.path.exists(GAME_EXE):
        messagebox.showerror("Error", f"{GAME_EXE} can't be found. Place the mod manager executable in the game root directory.")
        sys.exit(1)
    if not os.path.exists(ADDONS_DIR):
        messagebox.showerror("Error", f"Folder '{ADDONS_DIR}' can't be found. Be sure that the manager executable located in the game root directory.")
        sys.exit(1)
    if not os.path.exists(DISABLED_DIR):
        os.makedirs(DISABLED_DIR)


def scan_addons():
    active = set(os.listdir(ADDONS_DIR)) if os.path.exists(ADDONS_DIR) else set()
    inactive = set(os.listdir(DISABLED_DIR)) if os.path.exists(DISABLED_DIR) else set()

    # Check for duplicates
    duplicates = active & inactive
    if duplicates:
        messagebox.showerror("Error", f"Duplicates found in both addons and addons_disabled folders: {duplicates}")

    return list(active), list(inactive)


def write_config(active_addons):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        for addon in active_addons:
            f.write(f"addfile addons\\{addon}\n")


def update_config():
    active, _ = scan_addons()
    write_config(active)
    messagebox.showinfo("Success", f"Enabled autoload for {len(active)} addons.")


def disable_mods():
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
        messagebox.showinfo("Info", "Addons autoload disabled.")
    else:
        messagebox.showinfo("Info", "No ringexec.cfg file to delete..")


def move_addon(addon, source, dest):
    src_path = os.path.join(source, addon)
    dest_path = os.path.join(dest, addon)
    if os.path.exists(src_path):
        shutil.move(src_path, dest_path)
        refresh_lists()
    else:
        messagebox.showerror("Error", f"Cannot move {addon}!")


def refresh_lists():
    active, inactive = scan_addons()

    listbox_active.delete(0, tk.END)
    listbox_inactive.delete(0, tk.END)

    for a in active:
        listbox_active.insert(tk.END, a)
    for i in inactive:
        listbox_inactive.insert(tk.END, i)


def disable_addon():
    selection = listbox_active.curselection()
    if selection:
        addon = listbox_active.get(selection[0])
        move_addon(addon, ADDONS_DIR, DISABLED_DIR)


def enable_addon():
    selection = listbox_inactive.curselection()
    if selection:
        addon = listbox_inactive.get(selection[0])
        move_addon(addon, DISABLED_DIR, ADDONS_DIR)


def main():
    global root, listbox_active, listbox_inactive

    check_environment()

    # Define tkinter interface
    root = tk.Tk()
    root.title("Dr. Robotnik's Ring Racers addons manager")

    # Define an app icon if possible
    if os.path.exists(ICON_FILE):
        try:
            root.iconbitmap(ICON_FILE)
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
    listbox_inactive = tk.Listbox(lists_frame, width=50, height=15, selectmode=tk.SINGLE)

    listbox_active.grid(row=0, column=0, padx=5, pady=5)
    listbox_inactive.grid(row=0, column=2, padx=5, pady=5)

    # Button to move addons from addons or addons_disabled folders
    buttons_frame = tk.Frame(lists_frame)
    buttons_frame.grid(row=0, column=1, padx=5)

    btn_disable = tk.Button(buttons_frame, text="→ Disable", command=lambda: disable_addon())
    btn_enable = tk.Button(buttons_frame, text="← Enable", command=lambda: enable_addon())

    btn_disable.pack(pady=10)
    btn_enable.pack(pady=10)

    btn_refresh = tk.Button(frame, text="Refresh list", command=refresh_lists)
    btn_refresh.pack(pady=5)

    refresh_lists()

    root.mainloop()


if __name__ == "__main__":
    main()


