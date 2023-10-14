#!/bin/sh
# prepare pypi package for release
VERSION="$1"

# check version format is correct
vf="$(echo $VERSION | grep -E '[0-9]+\.[0-9]+\.[0-9]+' | wc -l)"
if [ "$vf" -eq "0" ]; then
    echo "[!] Error, version needs to be in format 0.0.0"
    exit
fi
echo "[+] Version format is valid."

echo "[+] Setting version $VERSION"
echo "[?] Press enter to make the change. We will modify reait, setup.py, and pyproject.toml."
read line

perl -i -pe "s/(?<=version.{0,10}\=.{0,10})[0-9]+\.[0-9]+\.[0-9]+/$VERSION/" ./src/reait/main.py
perl -i -pe "s/(?<=version.{0,10}\=.{0,10})[0-9]+\.[0-9]+\.[0-9]+/$VERSION/" ./src/reait/api.py
perl -i -pe "s/(?<=version.{0,10}\=.{0,10})[0-9]+\.[0-9]+\.[0-9]+/$VERSION/" ./setup.py
perl -i -pe "s/(?<=version.{0,10}\=.{0,10})[0-9]+\.[0-9]+\.[0-9]+/$VERSION/" ./pyproject.toml
