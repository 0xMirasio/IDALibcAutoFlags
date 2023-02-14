setlocal enableextensions
@echo off

echo Installing IDALibcFlags Windows version

set INSTALLDIR=%APPDATA%\\Hex-Rays\\IDA Pro\\plugins\
set TARGET="autolibcflags-windows.py"
set HOME_CACHE=%APPDATA%\\IdaAutoLibcFlags\\
set REGISTER_FILE="functions.json"

echo File will be installed at %INSTALLDIR%

if not exist "%INSTALLDIR%" (
    mkdir "%INSTALLDIR%"
    echo IDA Plugins directory created - OK
)

copy %TARGET% "%INSTALLDIR%"

echo Plugins installed - OK


if not exist "%HOME_CACHE%" (
    mkdir "%HOME_CACHE%"
    echo Cache created - OK
)

copy %REGISTER_FILE% "%HOME_CACHE%"
copy "enum" "%HOME_CACHE%"

echo Enum copied to cache - OK