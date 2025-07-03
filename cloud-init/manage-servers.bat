@echo off
REM filepath: /home/arww24/Documents/git/auto-MicroK8s/cloud-init/manage-servers.bat
rem This script is used to manage the servers for the Auto MicroK8s Cluster.
rem It assumes that Multipass is installed and configured on the system.
rem Running the script without parameters will check the status of the servers.
rem If the servers exist and are not running, it will start them.
rem If the servers do not exist, it will create new instances.
rem Running the script with the parameter "delete" will delete all MicroK8s servers.

setlocal enabledelayedexpansion

set SERVER_NAMES=aw6-server1 aw6-server2 aw6-server3

rem Check if delete parameter was passed
if /i "%1"=="delete" (
    echo Deleting all MicroK8s servers...
    for %%s in (%SERVER_NAMES%) do (
        echo Deleting %%s...
        multipass delete %%s
    )
    echo Purging deleted instances...
    multipass purge
    echo All servers deleted.
    goto :EOF
)

rem For each server, check its status and take appropriate action
for %%s in (%SERVER_NAMES%) do (
    echo Checking status of %%s...
    
    rem Check if the server exists
    multipass info %%s >nul 2>&1
    if !errorlevel! neq 0 (
        echo Server %%s does not exist. Creating new instance...
        multipass launch --name %%s --cpus 1 --memory 2G --disk 8G --cloud-init server.yaml
    ) else (
        rem Check the state of the server
        for /f "tokens=2 delims=:" %%a in ('multipass info %%s ^| findstr "State"') do (
            set STATE=%%a
            set STATE=!STATE:~1!
        )
        
        if "!STATE!"=="Running" (
            echo Server %%s is already running.
        ) else (
            echo Starting server %%s...
            multipass start %%s
        )
    )
)

echo.
echo Server status:
multipass list

endlocal


