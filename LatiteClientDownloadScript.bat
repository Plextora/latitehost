@:: Made by VastraKai#0001 for Latite Client/Injector

@title LatiteLauncher Downloader
@if /i not "%batdebug%" == "true" @echo off
setlocal EnableDelayedExpansion


set LatiteExeLocation=%userprofile%\Desktop\LatiteClient
set LatiteExeName=LatiteLauncher.exe
set LatiteFullPath=%LatiteExeLocation%\%LatiteExeName%
set InjectorLink=https://github.com/Imrglop/Latite-Releases/raw/main/injector/Injector.exe
set InjectorLinkBetter=https://github.com/Plextora/LatiteInjector/releases/latest/download/LatiteInjector.exe

call :checkPrivileges



:: =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- Start of batch file
if not exist "%LatiteExeLocation%" md "%LatiteExeLocation%"
cd /d "%LatiteExeLocation%"
echo Latite will be downloaded to: '%LatiteFullPath%'.
timeout -t 3  > nul


echo Adding exclusions to Windows Defender.
call :disable
>nul powershell Add-MpPreference -ExclusionProcess "cmd.exe"
if not "%errorlevel%" == "0" echo Failed to add exclusion. (Windows Defender is probably disabled already.)
>nul powershell Add-MpPreference -ExclusionProcess "powershell.exe"
if not "%errorlevel%" == "0" echo Failed to add exclusion. (Windows Defender is probably disabled already.)
>nul powershell Add-MpPreference -ExclusionPath "%LatiteExeLocation%"
if not "%errorlevel%" == "0" echo Failed to add exclusion. (Windows Defender is probably disabled already.)
>nul powershell Add-MpPreference -ExclusionProcess "%LatiteExeName%"
if not "%errorlevel%" == "0" echo Failed to add exclusion. (Windows Defender is probably disabled already.)
set msg=0
:wfr
call :get-process-state consent.exe
if "%errorlevel%" == "0" (
    if "%msg%" == "0" echo Please click YES on the remaining elevation prompts.
    set msg=1
    goto :wfr
)
call :enable

echo Downloading Latite Launcher...
taskkill /f /im "%LatiteExeName%" > nul 2>&1
> nul 2>&1 cmd /c curl "%InjectorLink%" -L -f -o "%LatiteExeName%"
if "%errorlevel%" == "0" goto :SkipBitsAdmin

echo WARNING: Failed to download using curl, falling back to bitsadmin.
start /wait "LatiteLauncher Downloader" cmd /c bitsadmin /TRANSFER LatiteDownload /DOWNLOAD %InjectorLink% "%LatiteFullPath%"
if not "%errorlevel%" == "0" (
    echo Download failed!
    pause
    goto :EOF
)
:SkipBitsAdmin

start "" "%LatiteFullPath%"
echo Latite Launcher has now on your desktop!
::start /min "" cmd /c "timeout -t 2 -nobreak > nul 2>&1 & del /f /q "%~dps0\%~nxs0""
timeout -t 1 > nul
goto :EOF


:checkPrivileges
net file 1>NUL 2>NUL
if '%errorlevel%' == '0' ( exit /b ) else ( goto getPrivileges )
goto :getPrivileges

:getPrivileges
echo.
echo =-=-=-=-=-=-=-=-=-=-=-=-=
echo Waiting for elevation...
echo Executing: "%~s0"
echo =-=-=-=-=-=-=-=-=-=-=-=-=

powershell.exe Start-Process cmd.exe -Verb RunAs -ArgumentList '/c "%~s0 & pause"'
if not "%errorlevel%" == "0" (
    echo Error: Elevation failed ^(%errorlevel%^). Please report this!
    echo Press any key to exit...
    pause > nul
    exit
)
exit

:: =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- For disabling or enabling windows defender, if needed.


:disable
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f > nul 2>&1
if "%errorlevel%" == "0" (
    goto :realdisable
) else (
    call :ilEcho You need to manually disable Tamper protection before you can continue.
    start "Windows Security" windowsdefender://threatsettings
)
:disloop
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f > nul 2>&1
if "%errorlevel%" == "0" (
    goto :realdisable
)
goto :disloop

:realdisable
Reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\State" /v "AccountProtection_MicrosoftAccount_Disconnected" /t REG_DWORD /d "0" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\State" /v "AccountProtection_MicrosoftAccount_Disconnected" /t REG_DWORD /d "0" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f > nul 2>&1	
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtectionSource" /t REG_DWORD /d "2" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates" /v "FirstAuGracePeriod" /t REG_DWORD /d "0" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /v "DisablePrivacyMode" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /t REG_BINARY /d "030000000000000000000000" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v "HideSystray" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d "0" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "RandomizeScheduleTaskTimes" /t REG_DWORD /d "0" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" /v "DisableAutoExclusions" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Quarantine" /v "LocalSettingOverridePurgeItemsAfterDelay" /t REG_DWORD /d "0" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Quarantine" /v "PurgeItemsAfterDelay" /t REG_DWORD /d "0" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScriptScanning" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation" /v "Scan_ScheduleDay" /t REG_DWORD /d "8" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation" /v "Scan_ScheduleTime" /t REG_DWORD /d 0 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "AdditionalActionTimeOut" /t REG_DWORD /d 0 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "CriticalFailureTimeOut" /t REG_DWORD /d 0 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d 1 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "NonCriticalTimeOut" /t REG_DWORD /d 0 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "AvgCPULoadFactor" /t REG_DWORD /d "10" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupFullScan" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupQuickScan" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableRemovableDriveScanning" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableRestorePoint" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningMappedNetworkDrivesForFullScan" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "PurgeItemsAfterDelay" /t REG_DWORD /d 0 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "ScanOnlyIfIdle" /t REG_DWORD /d 0 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "ScanParameters" /t REG_DWORD /d 0 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "ScheduleDay" /t REG_DWORD /d 8 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "ScheduleTime" /t REG_DWORD /d 0 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableUpdateOnStartupWithoutEngine" /t REG_DWORD /d 1 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleDay" /t REG_DWORD /d 8 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleTime" /t REG_DWORD /d 0 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureUpdateCatchupInterval" /t REG_DWORD /d 0 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d 0 /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReportingLocation" /t REG_MULTI_SZ /d "0" /f > nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f > nul 2>&1
Reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f > nul 2>&1
Reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f > nul 2>&1
if exist C:\windows\system32\taskkilll.exe taskkilll /f /fi "WINDOWTITLE eq Windows Security" > nul 2>&1
if exist C:\windows\system32\taskkill.exe taskkill /f /fi "WINDOWTITLE eq Windows Security" > nul 2>&1
exit /b




:enable
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Security Health\State" /v "AccountProtection_MicrosoftAccount_Disconnected" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /f 	> nul 2>&1
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtectionSource" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates" /v "FirstAuGracePeriod" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /v "DisablePrivacyMode" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v "HideSystray" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "PUAProtection" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "RandomizeScheduleTaskTimes" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" /v "DisableAutoExclusions" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Quarantine" /v "LocalSettingOverridePurgeItemsAfterDelay" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Quarantine" /v "PurgeItemsAfterDelay" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScriptScanning" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation" /v "Scan_ScheduleDay" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation" /v "Scan_ScheduleTime" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "AdditionalActionTimeOut" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "CriticalFailureTimeOut" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "NonCriticalTimeOut" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "AvgCPULoadFactor" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupFullScan" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupQuickScan" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableRemovableDriveScanning" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableRestorePoint" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningMappedNetworkDrivesForFullScan" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningNetworkFiles" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "PurgeItemsAfterDelay" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "ScanOnlyIfIdle" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "ScanParameters" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "ScheduleDay" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "ScheduleTime" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableUpdateOnStartupWithoutEngine" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleDay" /f > nul 2>&1 
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleTime" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureUpdateCatchupInterval" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReportingLocation" /f > nul 2>&1
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /f > nul 2>&1
Reg delete "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /f > nul 2>&1
Reg delete "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /f > nul 2>&1
net start WinDefend > nul 2>&1
if exist C:\windows\system32\taskkilll.exe taskkilll /f /fi "WINDOWTITLE eq Windows Security" > nul 2>&1
if exist C:\windows\system32\taskkill.exe taskkill /f /fi "WINDOWTITLE eq Windows Security" > nul 2>&1
exit /b


:ilEcho <STRING>
for /f %%a in ('copy /Z "%~dpf0" nul') do set "ASCII_13=%%a"
for /F %%C in ('copy /Z "%~f0" nul') do set "CR=%%C"
for /F %%C in ('echo prompt $H ^| cmd') do set "BS=%%C"
set "STRING=%*"
set "SPACES=                                                                                                      "
set /P ="%BS%!CR!%SPACES%!CR!" < nul
set /p <nul =%STRING%
exit /B


:get-process-state <ImageName>
tasklist /fi "ImageName eq %1" /fo csv 2>NUL | find /I "%1">NUL
if "%ERRORLEVEL%"=="0" (
    set err=0
) else (
    set err=1
)
exit /b %err%
