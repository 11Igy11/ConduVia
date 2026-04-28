[Setup]
AppName=ViaNyquist
AppVersion=0.1.0
AppPublisher=Igy
DefaultDirName={autopf}\ViaNyquist
DefaultGroupName=ViaNyquist
OutputDir=output
OutputBaseFilename=ViaNyquist_Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\assets\ViaNyquist.ico
UninstallDisplayIcon={app}\ViaNyquist.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional options:"
Name: "installai"; Description: "Install AI support (Ollama)"; GroupDescription: "Additional options:"
Name: "pullmodel"; Description: "Download recommended AI model (llama3)"; GroupDescription: "Additional options:"; Flags: unchecked

[Files]
Source: "..\dist\main.exe"; DestDir: "{app}"; DestName: "ViaNyquist.exe"; Flags: ignoreversion
Source: "third_party\OllamaSetup.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
Name: "{group}\ViaNyquist"; Filename: "{app}\ViaNyquist.exe"
Name: "{autodesktop}\ViaNyquist"; Filename: "{app}\ViaNyquist.exe"; Tasks: desktopicon

[Run]
Filename: "{tmp}\OllamaSetup.exe"; Description: "Install Ollama"; Flags: waituntilterminated postinstall skipifsilent; Tasks: installai
Filename: "{cmd}"; Parameters: "/C ""%LOCALAPPDATA%\Programs\Ollama\ollama.exe"" pull llama3"; Description: "Download AI model (llama3)"; Flags: waituntilterminated postinstall skipifsilent; Tasks: installai and pullmodel
Filename: "{app}\ViaNyquist.exe"; Description: "Launch ViaNyquist"; Flags: nowait postinstall skipifsilent