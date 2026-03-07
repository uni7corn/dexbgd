@echo off
REM push.bat -- Push the built .so directly into the installed app's lib dir.
REM Requires root (Magisk).  No APK reinstall needed.
REM
REM Usage:
REM   scripts\push.bat                        -- pushes to com.test.profiletest
REM   scripts\push.bat com.example.otherapp  -- pushes to a different package

setlocal enabledelayedexpansion

set "TARGET_PKG=%~1"
if "%TARGET_PKG%"=="" set "TARGET_PKG=com.test.profiletest"

set "AGENT_NAME=libart_jit_tracer.so"
set "LOCAL_SO=%~dp0..\build\%AGENT_NAME%"

if not exist "%LOCAL_SO%" (
    echo ERROR: %LOCAL_SO% not found -- run scripts\build.bat first
    exit /b 1
)

REM Resolve installed lib dir from pm path:
REM   package:/data/app/~~HASH/com.test.profiletest-HASH/base.apk
REM   ->      /data/app/~~HASH/com.test.profiletest-HASH/lib/arm64/
set "SO_PATH="
for /f "tokens=*" %%S in ('adb shell "d=$(pm path %TARGET_PKG% | cut -d: -f2); echo $(dirname $d)/lib/arm64/%AGENT_NAME%" 2^>nul') do set "SO_PATH=%%S"

if not defined SO_PATH (
    echo ERROR: could not resolve .so path for %TARGET_PKG%
    exit /b 1
)
echo [*] Device path: %SO_PATH%

echo [*] Pushing %AGENT_NAME%...
adb push "%LOCAL_SO%" /data/local/tmp/%AGENT_NAME%
if errorlevel 1 ( echo ERROR: adb push failed & exit /b 1 )

echo [*] Copying to app lib dir (root)...
adb shell su -c "cp /data/local/tmp/%AGENT_NAME% %SO_PATH%"
if errorlevel 1 ( echo ERROR: root copy failed & exit /b 1 )

echo [*] Done. %AGENT_NAME% deployed to %TARGET_PKG%.
