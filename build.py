import subprocess
import os

cmd = [
    "pyinstaller",
    "--onefile",
    "--noconsole",
    "--icon=assets/icon.ico",
    "--add-data", "assets/icon.ico;.",
    "code/addons-manager.py",
]

subprocess.run(cmd, check=True)
