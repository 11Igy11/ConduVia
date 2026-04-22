[Setup]
AppName=ConduVia
AppVersion=0.1.0
AppPublisher=Igy
DefaultDirName={autopf}\ConduVia
DefaultGroupName=ConduVia
OutputDir=output
OutputBaseFilename=ConduVia_Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\assets\ConduVia.ico
UninstallDisplayIcon={app}\ConduVia.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "..\dist\ConduVia\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\ConduVia"; Filename: "{app}\ConduVia.exe"
Name: "{autodesktop}\ConduVia"; Filename: "{app}\ConduVia.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\ConduVia.exe"; Description: "Launch ConduVia"; Flags: nowait postinstall skipifsilent