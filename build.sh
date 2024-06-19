#!/bin/bash
python -m build .

#bundle into executable
pyinstaller -F --name reait ./src/reait/main.py
