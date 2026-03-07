@echo off
REM attach.bat -- Attach the dexbgd agent to a target app
REM
REM Usage:
REM   scripts\attach.bat <package_name>             -- normal attach (app must be running)
REM   scripts\attach.bat <package_name> --quick     -- force-stop, fresh start, attach ASAP
REM   scripts\attach.bat <package_name> --sigstop   -- like --quick but SIGSTOP the process
REM                                                    immediately on PID appearance so agent
REM                                                    attaches while app is frozen (needs root)
REM
REM NOTE: --suspended (am start -D) does NOT work on Android 14 -- JDWP freezes the
REM       Binder thread so attach-agent is never processed.
REM       Use --sigstop instead: freezes with SIGSTOP after attach-agent, resumes after socket ready.
REM
REM For catching very early startup (e.g. MainActivity.onCreate on a simple app):
REM   Add to Application.onCreate in the testapp:
REM       if (BuildConfig.DEBUG) { android.os.SystemClock.sleep(4000); }
REM   This gives a stable 4-second window for --quick to attach.

setlocal enabledelayedexpansion

set "TARGET_PKG=%~1"
if "%TARGET_PKG%"=="" set "TARGET_PKG=com.test.profiletest"
set "AGENT_NAME=libart_jit_tracer.so"

REM Verify package is installed
for /f "tokens=*" %%A in ('adb shell pm path %TARGET_PKG% 2^>nul') do set "PKG_LINE=%%A"
if not defined PKG_LINE (
    echo ERROR: Package %TARGET_PKG% not found on device
    exit /b 1
)
echo [*] Package: %TARGET_PKG%

if /i "%~2"=="--quick"    goto :quick
if /i "%~2"=="--sigstop"  goto :sigstop
if /i "%~2"=="--ptrace"   goto :ptrace

REM ---- Normal path: ensure app is running, then attach -------------------------
set "PID="
for /f "tokens=*" %%P in ('adb shell pidof %TARGET_PKG% 2^>nul') do set "PID=%%P"
if not defined PID (
    echo [*] App not running, starting it...
    adb shell am start -n %TARGET_PKG%/.MainActivity
    timeout /t 2 /nobreak >nul
    for /f "tokens=*" %%P in ('adb shell pidof %TARGET_PKG% 2^>nul') do set "PID=%%P"
    if not defined PID (
        echo ERROR: Failed to start %TARGET_PKG%
        exit /b 1
    )
)
echo [*] PID: !PID!
echo [*] Attaching agent...
adb shell cmd activity attach-agent %TARGET_PKG% %AGENT_NAME%
echo [*] Agent attached.
goto :eof

REM ---- Quick path: fresh start, attach as fast as possible --------------------
REM Pre-establish adb forward so TUI connects the instant the agent socket appears.
REM The TUI (started first) handles connection polling -- no socket poll needed here.
:quick
echo [*] Pre-establishing port forward...
adb forward tcp:12345 localabstract:dexbgd

echo [*] Force-stopping %TARGET_PKG%...
adb shell am force-stop %TARGET_PKG%
timeout /t 1 /nobreak >nul

echo [*] Starting %TARGET_PKG%...
adb shell am start -n %TARGET_PKG%/.MainActivity

echo [*] Waiting for process (tight loop)...
set "PID="
:pid_loop_q
for /f "tokens=*" %%P in ('adb shell pidof %TARGET_PKG% 2^>nul') do set "PID=%%P"
if not defined PID goto :pid_loop_q

echo [*] PID: !PID! -- attaching agent immediately...
adb shell cmd activity attach-agent %TARGET_PKG% %AGENT_NAME%

echo.
echo [*] Attach command sent. TUI will connect automatically when socket appears.
echo [*] Deferred breakpoints activate when the target class first loads.
goto :eof

REM ---- Sigstop path: fresh start, SIGSTOP on PID, attach, SIGCONT -------------
REM Requires Magisk root (adb shell su -c ...).
REM Flow:
REM   1. Start app fresh (no -D, so no JDWP Binder freeze)
REM   2. SIGSTOP the process the instant PID appears -- freezes all threads
REM   3. SIGCONT to let the process run just enough for attach-agent Binder call
REM      (attach-agent sends the command; the Binder thread processes it after SIGCONT)
REM   4. Poll for socket; SIGSTOP again once socket appears
REM   5. TUI connects and sets breakpoints while process is frozen
REM   6. Run resume.bat to SIGCONT and let the app proceed
:sigstop
echo [*] Pre-establishing port forward...
adb forward tcp:12345 localabstract:dexbgd

echo [*] Force-stopping %TARGET_PKG%...
adb shell am force-stop %TARGET_PKG%
timeout /t 1 /nobreak >nul

echo [*] Starting %TARGET_PKG%...
adb shell am start -n %TARGET_PKG%/.MainActivity

echo [*] Waiting for process (tight loop)...
set "PID="
:pid_loop_s
for /f "tokens=*" %%P in ('adb shell pidof %TARGET_PKG% 2^>nul') do set "PID=%%P"
if not defined PID goto :pid_loop_s

echo [*] PID: !PID! -- sending SIGSTOP...
adb shell su -c "kill -STOP !PID!"

echo [*] Attaching agent (SIGCONT briefly to let Binder thread run)...
adb shell su -c "kill -CONT !PID!"
adb shell cmd activity attach-agent %TARGET_PKG% %AGENT_NAME%

echo [*] Polling for agent socket (up to 30s)...
set "SOCKET_READY="
for /l %%j in (1,1,30) do (
    if not defined SOCKET_READY (
        for /f "tokens=*" %%S in ('adb shell grep dexbgd /proc/net/unix') do set "SOCKET_READY=1"
        if not defined SOCKET_READY timeout /t 1 /nobreak >nul
    )
)
if not defined SOCKET_READY (
    echo ERROR: Agent socket @dexbgd not found after 30s
    echo Check: adb logcat -s ArtJitTracer
    exit /b 1
)

echo [*] Socket ready. Freezing app again...
adb shell su -c "kill -STOP !PID!"

echo.
echo [*] App is frozen. TUI will auto-connect and set breakpoints.
echo [*] When ready to resume the app run:
echo     scripts\resume.bat %TARGET_PKG%
goto :eof

REM ---- Ptrace path: inject .so directly via ptrace while process runs --------
REM Requires: dexbgd-inject binary pushed to /data/local/tmp/ (injector\build.bat)
REM           Magisk root (adb shell su)
REM Flow:
REM   1. Fresh start (no -D, no SIGSTOP -- process runs normally)
REM   2. Tight PID loop
REM   3. dexbgd-inject pauses the main thread via PTRACE_INTERRUPT,
REM      calls dlopen() inside the target, then detaches.
REM      All other threads (Binder, GC) keep running during the injection.
REM   4. Agent JNI_OnLoad runs, socket appears
REM   5. TUI connects, sets breakpoints
:ptrace
set "INJECT_BIN=/data/local/tmp/dexbgd-inject"

REM Derive .so path from pm path output:
REM   package:/data/app/~~HASH/com.test.profiletest-1/base.apk
REM   →  /data/app/~~HASH/com.test.profiletest-1/lib/arm64/libart_jit_tracer.so
set "SO_PATH="
for /f "tokens=*" %%S in ('adb shell "d=$(pm path %TARGET_PKG% ^| cut -d: -f2); echo $(dirname $d)/lib/arm64/%AGENT_NAME%"') do set "SO_PATH=%%S"
if not defined SO_PATH (
    echo ERROR: Could not resolve .so path for %TARGET_PKG%
    exit /b 1
)
echo [*] .so path: %SO_PATH%

echo [*] Pre-establishing port forward...
adb forward tcp:12345 localabstract:dexbgd

echo [*] Force-stopping %TARGET_PKG%...
adb shell am force-stop %TARGET_PKG%
timeout /t 1 /nobreak >nul

echo [*] Starting %TARGET_PKG%...
adb shell am start -n %TARGET_PKG%/.MainActivity

echo [*] Waiting for process (tight loop)...
set "PID="
:pid_loop_p
for /f "tokens=*" %%P in ('adb shell pidof %TARGET_PKG% 2^>nul') do set "PID=%%P"
if not defined PID goto :pid_loop_p
echo [*] PID: !PID!

echo [*] Injecting agent via ptrace...
REM Injector pauses the main thread while the agent socket thread runs.
REM It will print "press Enter to resume" -- do so after connecting TUI and setting bps.
adb shell su -c "%INJECT_BIN% !PID! %SO_PATH%"
if errorlevel 1 (
    echo ERROR: inject failed -- see output above
    exit /b 1
)

echo.
echo [*] Done. App is running.
goto :eof
