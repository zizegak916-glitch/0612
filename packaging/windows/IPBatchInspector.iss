#ifndef MyAppVersion
  #define MyAppVersion "4.0.0"
#endif

[Setup]
AppId={{8B19A957-B52A-462B-A067-7CFA8DAA9217}
AppName=IPBatchInspector
AppVersion={#MyAppVersion}
AppPublisher=IPBatchInspector contributors
AppPublisherURL=https://github.com/zizegak916-glitch/0612
AppSupportURL=https://github.com/zizegak916-glitch/0612/issues
DefaultDirName={localappdata}\Programs\IPBatchInspector
DefaultGroupName=IPBatchInspector
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\release
OutputBaseFilename=IPBatchInspector-{#MyAppVersion}-Windows-x64-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\..\LICENSE
UninstallDisplayIcon={app}\IPBatchInspector.exe
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\..\dist\IPBatchInspector.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dist\ipbatch-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\IPBatchInspector"; Filename: "{app}\IPBatchInspector.exe"
Name: "{group}\IPBatchInspector CLI"; Filename: "{cmd}"; Parameters: "/K ""{app}\ipbatch-cli.exe"" --help"; WorkingDir: "{app}"
Name: "{autodesktop}\IPBatchInspector"; Filename: "{app}\IPBatchInspector.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加图标："; Flags: unchecked

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\IPBatchInspector.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\IPBatchInspector.exe"; Flags: uninsdeletekey

[Run]
Filename: "{app}\IPBatchInspector.exe"; Description: "启动 IPBatchInspector"; Flags: nowait postinstall skipifsilent
