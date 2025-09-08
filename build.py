import subprocess
import os

env = os.environ.copy()

env["DEV_MODE"] = "false"

cmd = [
    "pyinstaller",
    "--onefile",
    "--noconsole",
    "--icon=code/icon.ico",
    "--add-data",
    "code/icon.ico;.",
    "code/addons-manager.py",
]

subprocess.run(cmd, check=True)
