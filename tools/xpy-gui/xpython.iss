; Inno Setup script: makes xpython-setup.exe, the Windows installer for xpython.exe.
; build_windows.bat runs it after PyInstaller (which puts xpython.exe in work\dist).
#define AppName "xPython tools"
#define AppVersion "1.0.0"
#define AppExe "xpython.exe"

[Setup]
AppId={{6D2C9A51-3B0E-4E6B-9C4D-7F1A2E8B5C30}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=xPython project
DefaultDirName={autopf}\xPython
DefaultGroupName=xPython
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\xpython.ico
OutputDir=dist
OutputBaseFilename=xpython-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=icon\xpython.ico
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Installing for "all users" needs administrator rights; the user can choose "just me"
PrivilegesRequiredOverridesAllowed=dialog

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "work\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon\xpython.ico"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
; The data folder: keys\, server\, apps\, build\ (never removed by the uninstaller)
Name: "{userdocs}\xPython"; Flags: uninsneveruninstall

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"; IconFilename: "{app}\xpython.ico"
Name: "{group}\xPython data folder"; Filename: "{userdocs}\xPython"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; IconFilename: "{app}\xpython.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Start {#AppName} now"; Flags: nowait postinstall skipifsilent

[Messages]
FinishedLabel=Setup has installed [name] on your computer.%n%nYour keys, server certificates and apps go in Documents\xPython. Keep that folder private and backed up: the uninstaller never deletes it.
