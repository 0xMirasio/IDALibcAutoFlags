#!/bin/bash

TARGET="autolibcflags.py"
USEWINE=1

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