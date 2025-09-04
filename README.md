# dr-robotnik-ring-racers-addons-manager
A tool to enable or disable addons and especially, make them autloadable so you don't have to generate an autload list manually.

Built with Pyinstaller

Command: `pyinstaller --onefile --noconsole --icon=icon.ico --add-data "icon.ico;." manager.py`

Requirements:
Python 3.10.5
PyInstaller 6.15.0

All code dependencies are shipped with default Python

# How to use
- Place the manager executable in the game root folder and execute it.
- All the files from your addons folder should appear in the left column.
- To disable an addon, just move it inside the right column.
- To enable or update the autoloading feature, click "Enable/Update autoloader".
- Clicking "Disable autoloader" will prevent the addons to be loaded on launch. But all enabled addons will remain in the addons folder and be anble to be enabled from the in game loader.
