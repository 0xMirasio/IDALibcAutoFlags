#!/bin/bash

TARGET="autolibcflags.py"
HOME_CACHE="$HOME/.cache/AutoLibcFlags/"
REGISTER_FILE="functions.json"
INSTALLDIR="$HOME/.idapro/plugins/"


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