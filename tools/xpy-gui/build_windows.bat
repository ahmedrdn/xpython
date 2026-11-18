@echo off
rem Builds the xPython tools INSTALLER: dist\xpython-setup.exe
rem (GUI + officer + pack + ota + mpremote + esptool in one program, installed by Inno Setup).
rem Run it on Windows, from anywhere. Needs:
rem   Python 3.13+ from python.org ("Add python.exe to PATH" ticked)
rem   Inno Setup 6 from https://jrsoftware.org/isdl.php
setlocal
set "HERE=%~dp0"
cd /d "%HERE%"

set "ICON=%HERE%icon\xpython.ico"
if not exist "%ICON%" (
  echo ERROR: icon not found: %ICON%
  goto :error
)
set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
  echo ERROR: Inno Setup 6 not found. Install it from https://jrsoftware.org/isdl.php
  goto :error
)
echo Using icon: %ICON%

python -m pip install --upgrade -r requirements-windows.txt || goto :error

rem 1. The program (in a work folder: it is not handed out on its own)
if exist work rmdir /s /q work
python -m PyInstaller --noconfirm --clean --onefile --windowed --name xpython ^
  --distpath "%HERE%work\dist" --workpath "%HERE%work\build" --specpath "%HERE%work" ^
  --icon "%ICON%" ^
  --add-data "%HERE%icon\xpython.png;tools\xpy-gui\icon" ^
  --add-data "%HERE%..\xpy-officer\xpy_officer.py;tools\xpy-officer" ^
  --add-data "%HERE%..\xpy-pack\xpy_pack.py;tools\xpy-pack" ^
  --add-data "%HERE%..\xpy-ota\xpy_ota.py;tools\xpy-ota" ^
  --collect-all mpremote --collect-all esptool --collect-submodules serial ^
  "%HERE%xpy_gui.py" || goto :error

rem 2. The installer
"%ISCC%" "%HERE%xpython.iss" || goto :error
echo.
echo Done: %HERE%dist\xpython-setup.exe
echo (If Explorer still shows an old icon, that is its icon cache: run  ie4uinit.exe -show)
goto :eof
:error
echo Build FAILED.
exit /b 1
