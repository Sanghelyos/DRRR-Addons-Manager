import subprocess

cmd = [
    "pyinstaller",
    "--onefile",
    "--noconsole",
    "--icon=assets/icon.ico",
    "--add-data", "assets/icon.ico;assets",
    "code/sanghelyos-toolbox.py",
]

subprocess.run(cmd, check=True)