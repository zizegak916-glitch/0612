#ifndef MyAppVersion
  #define MyAppVersion "6.0.0-alpha.2"
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
Source: "..\..\monitor.example.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\scripts\install_service_windows.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion

[Icons]
Name: "{group}\IPBatchInspector"; Filename: "{app}\IPBatchInspector.exe"
Name: "{group}\IPBatchInspector CLI"; Filename: "{cmd}"; Parameters: "/K ""{app}\ipbatch-cli.exe"" --help"; WorkingDir: "{app}"
Name: "{autodesktop}\IPBatchInspector"; Filename: "{app}\IPBatchInspector.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加图标："; Flags: unchecked
Name: "backgroundmonitor"; Description: "登录后运行后台调查监控（普通用户计划任务）"; GroupDescription: "后台集成："; Flags: unchecked

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\IPBatchInspector.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\IPBatchInspector.exe"; Flags: uninsdeletekey

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\install_service_windows.ps1"" -CliPath ""{app}\ipbatch-cli.exe"""; Description: "注册当前用户后台监控"; Flags: runhidden; Tasks: backgroundmonitor
Filename: "{app}\IPBatchInspector.exe"; Description: "启动 IPBatchInspector"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Unregister-ScheduledTask -TaskName 'IPBatchInspector Monitor' -Confirm:$false -ErrorAction SilentlyContinue"""; Flags: runhidden
