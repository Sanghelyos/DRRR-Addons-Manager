# Dr. Robotnik's Ring Racers Addons Manager
## Now works with Sonic Robo Blast 2 Kart too!!
A tool to enable or disable addons and especially, make them autoloadable so you don't have to generate an autoload list manually.

Latest version [download](https://github.com/Sanghelyos/dr-robotnik-ring-racers-addons-manager/releases/latest)

Build command: `python build.py`

### Requirements
- Python 3.10.5
- PyInstaller 6.15.0

# How to use
- Place the manager executable in the game root folder and execute it.
- All the files from your addons folder should appear in the left column. A folder will be created if it doesn't exists.
- To disable an addon, just move it inside the right column.
- To enable or update the autoloading feature, click "Enable/Update autoloader".
- Clicking "Disable autoloader" will prevent the addons to be loaded on launch. But all enabled addons will remain in the addons folder and be anble to be enabled from the in game loader.
