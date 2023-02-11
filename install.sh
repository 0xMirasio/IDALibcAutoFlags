#!/bin/bash

TARGET="autolibcflags.py"
USEWINE=1
HOME_CACHE="$HOME/.cache/AutoLibcFlags/"
REGISTER_FILE="functions.json"

if [ $USEWINE -eq 1 ]; then
    INSTALLDIR="$HOME/.wine/drive_c/users/$USER/AppData/Roaming/Hex-Rays/IDA Pro/plugins/" 
else
    INSTALLDIR="$HOME/.idapro/plugins/"
fi


echo "File will be installed to $INSTALLDIR"

if [ ! -d "$INSTALLDIR" ]; then
  mkdir -p "$INSTALLDIR"
fi



cp $TARGET "$INSTALLDIR"
echo "Copied files to ida plugins directory"

if [ ! -d "$HOME_CACHE" ]; then
  mkdir -p "$HOME_CACHE"
else
  rm -rf "$HOME_CACHE"
fi

cp -r "enum" "$HOME_CACHE"
echo "copied enum files to $HOME_CACHE"

cp "$REGISTER_FILE" "$HOME_CACHE"
echo "copied functions.json to $HOME_CACHE"