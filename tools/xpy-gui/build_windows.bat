@echo off
rem Builds xpython.exe: the xPython tools (GUI + officer + pack + ota + mpremote + esptool)
rem in ONE file. Run it on Windows, from this folder (tools\xpy-gui), with Python 3.13+
rem installed from python.org ("Add python.exe to PATH" ticked).
setlocal
cd /d "%~dp0"
python -m pip install --upgrade -r requirements-windows.txt || goto :error
python -m PyInstaller --noconfirm --clean --onefile --windowed --name xpython ^
  --add-data "..\xpy-officer\xpy_officer.py;tools\xpy-officer" ^
  --add-data "..\xpy-pack\xpy_pack.py;tools\xpy-pack" ^
  --add-data "..\xpy-ota\xpy_ota.py;tools\xpy-ota" ^
  --collect-all mpremote --collect-all esptool --collect-submodules serial ^
  --hidden-import cryptography.hazmat.primitives.asymmetric.ec ^
  --hidden-import cryptography.x509 ^
  xpy_gui.py || goto :error
echo.
echo Done: %~dp0dist\xpython.exe
rem The installer (xpython-setup.exe), if Inno Setup 6 is installed
set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if exist "%ISCC%" (
  "%ISCC%" xpython.iss || goto :error
  echo Installer: %~dp0dist\xpython-setup.exe
) else (
  echo No Inno Setup 6 found: only xpython.exe was made. Get it from https://jrsoftware.org/isdl.php
)
goto :eof
:error
echo Build FAILED.
exit /b 1
