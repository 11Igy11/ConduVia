[Setup]
AppId={{D9054D7D-5B2D-4B5D-A518-4DE5C3C0A6B2}
AppName=ViaNyquist
AppVersion=0.1.0
AppPublisher=Igy
AppPublisherURL=https://github.com/11Igy11/ViaNyquist
AppSupportURL=https://github.com/11Igy11/ViaNyquist
AppUpdatesURL=https://github.com/11Igy11/ViaNyquist
DefaultDirName={autopf}\ViaNyquist
DefaultGroupName=ViaNyquist
OutputDir=output
OutputBaseFilename=ViaNyquist_Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\assets\ViaNyquist.ico
WizardImageFile=assets\wizard-image.bmp
WizardSmallImageFile=assets\wizard-small.bmp
UninstallDisplayIcon={app}\ViaNyquist.exe
VersionInfoVersion=0.1.0
VersionInfoCompany=Igy
VersionInfoDescription=ViaNyquist beta installer
VersionInfoProductName=ViaNyquist
DisableProgramGroupPage=yes
UsePreviousAppDir=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional options:"
Name: "installai"; Description: "Install AI support (Ollama)"; GroupDescription: "Additional options:"
Name: "pullmodel"; Description: "Download recommended AI model (llama3)"; GroupDescription: "Additional options:"; Flags: unchecked

[Files]
Source: "..\dist\ViaNyquist\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "third_party\OllamaSetup.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall skipifsourcedoesntexist; Tasks: installai

[Icons]
Name: "{group}\ViaNyquist"; Filename: "{app}\ViaNyquist.exe"
Name: "{autodesktop}\ViaNyquist"; Filename: "{app}\ViaNyquist.exe"; Tasks: desktopicon

[Run]
Filename: "{tmp}\OllamaSetup.exe"; Description: "Install Ollama"; Flags: waituntilterminated postinstall skipifsilent; Tasks: installai; Check: FileExists(ExpandConstant('{tmp}\OllamaSetup.exe'))
Filename: "{cmd}"; Parameters: "/C ""%LOCALAPPDATA%\Programs\Ollama\ollama.exe"" pull llama3"; Description: "Download AI model (llama3)"; Flags: waituntilterminated postinstall skipifsilent; Tasks: installai and pullmodel
Filename: "{app}\ViaNyquist.exe"; Description: "Launch ViaNyquist"; Flags: nowait postinstall skipifsilent
