#/bin/bash
python3 -m build .

#bundle into executable
pyinstaller -F --name reait ./src/reait/main.py
