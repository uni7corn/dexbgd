@echo off
REM build.bat — Configure and build the JIT tracer agent for Android arm64
REM
REM Usage: scripts\build.bat
REM   Set ANDROID_NDK_HOME before running, or edit the fallback below.

setlocal

set "SCRIPT_DIR=%~dp0"
set "PROJECT_DIR=%SCRIPT_DIR%.."
set "BUILD_DIR=%PROJECT_DIR%\build"

if "%ANDROID_NDK_HOME%"=="" (
    echo ERROR: ANDROID_NDK_HOME is not set.
    echo   set ANDROID_NDK_HOME=C:\path\to\android-ndk-r26d
    exit /b 1
)

set "TOOLCHAIN=%ANDROID_NDK_HOME%\build\cmake\android.toolchain.cmake"
if not exist "%TOOLCHAIN%" (
    echo ERROR: Toolchain file not found: %TOOLCHAIN%
    exit /b 1
)

REM Use Ninja generator — Visual Studio generator does not work for NDK cross-compilation.
REM Ninja ships with the Android SDK at sdk\cmake\<version>\bin\ninja.exe
REM or can be installed standalone (e.g. choco install ninja, or scoop install ninja).
set "CMAKE_MAKE_PROGRAM="
if exist "%ANDROID_NDK_HOME%\..\cmake" (
    for /d %%D in ("%ANDROID_NDK_HOME%\..\cmake\*") do (
        if exist "%%D\bin\ninja.exe" set "CMAKE_MAKE_PROGRAM=-DCMAKE_MAKE_PROGRAM=%%D\bin\ninja.exe"
    )
)

echo [*] Configuring (arm64-v8a, API 34, Ninja)...
cmake -B "%BUILD_DIR%" -S "%PROJECT_DIR%" -G Ninja ^
    -DCMAKE_TOOLCHAIN_FILE="%TOOLCHAIN%" ^
    %CMAKE_MAKE_PROGRAM% ^
    -DANDROID_ABI=arm64-v8a ^
    -DANDROID_PLATFORM=android-34 ^
    -DANDROID_STL=c++_static
if errorlevel 1 (
    echo ERROR: CMake configure failed.
    exit /b 1
)

echo [*] Building...
cmake --build "%BUILD_DIR%"
if errorlevel 1 (
    echo ERROR: Build failed.
    exit /b 1
)

echo [+] Built: %BUILD_DIR%\libart_jit_tracer.so
endlocal
