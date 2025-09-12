import subprocess

cmd = [
    "pyinstaller",
    "--onefile",
    "--noconsole",
    "--icon=assets/icon.ico",
    "--add-data", "assets/icon.ico;assets",
    "code/addons-manager.py",
]

subprocess.run(cmd, check=True)