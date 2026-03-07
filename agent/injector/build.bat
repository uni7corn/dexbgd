@echo off
REM Build dexbgd-inject for arm64 Android using the NDK.
REM Requires ANDROID_NDK_HOME to be set.
REM Output: build\dexbgd-inject  (push to /data/local/tmp/ on device)

setlocal

set "NDK=%ANDROID_NDK_HOME%"
if not defined NDK (
    echo ERROR: ANDROID_NDK_HOME is not set
    exit /b 1
)

REM cd into the injector directory so all paths are relative (avoids trailing-backslash quote bug)
cd /d "%~dp0"

cmake -G Ninja ^
    -DCMAKE_TOOLCHAIN_FILE="%NDK%\build\cmake\android.toolchain.cmake" ^
    -DANDROID_ABI=arm64-v8a ^
    -DANDROID_PLATFORM=android-26 ^
    -DCMAKE_BUILD_TYPE=Release ^
    -B build ^
    -S .

if errorlevel 1 ( echo [!] cmake configure failed & exit /b 1 )

cmake --build build
if errorlevel 1 ( echo [!] build failed & exit /b 1 )

echo.
echo [*] Built: %~dp0build\dexbgd-inject
echo [*] Push:  adb push "%~dp0build\dexbgd-inject" /data/local/tmp/dexbgd-inject
echo [*] Then:  adb shell chmod +x /data/local/tmp/dexbgd-inject
