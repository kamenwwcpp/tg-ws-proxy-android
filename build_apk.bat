@echo off
setlocal enabledelayedexpansion

echo === TG WS Proxy APK Build Script ===
echo === Output: 3 APKs (universal, arm64-v8a, armeabi-v7a) ===
echo.

set "VERSION_NAME="
for /f "tokens=2 delims==" %%V in ('findstr /R /C:"versionName *= *\".*\"" "app\build.gradle.kts"') do (
    set "VERSION_NAME=%%V"
)
set "VERSION_NAME=%VERSION_NAME:"=%"
set "VERSION_NAME=%VERSION_NAME: =%"
if not defined VERSION_NAME (
    echo ERROR: Could not read versionName from app\build.gradle.kts
    pause
    exit /b 1
)
set "RELEASE_PREFIX=v%VERSION_NAME%-android"
echo Version: %VERSION_NAME%
echo Base prefix: %RELEASE_PREFIX%
echo.

set "MISSING=0"
if not exist "app\src\main\jniLibs\arm64-v8a\libtgwsproxy.so" (
    echo ERROR: arm64-v8a .so not found!
    set "MISSING=1"
)
if not exist "app\src\main\jniLibs\armeabi-v7a\libtgwsproxy.so" (
    echo ERROR: armeabi-v7a .so not found!
    set "MISSING=1"
)

if "%MISSING%"=="1" (
    echo.
    echo Run build_so.bat first to build all native libraries!
    pause
    exit /b 1
)

echo Incremental build...
echo Building release APKs...
call gradlew assembleRelease --no-daemon

if %errorlevel% neq 0 (
    echo.
    echo BUILD FAILED! Please check the errors above.
    pause
    exit /b 1
)

if not exist "app\release" mkdir "app\release"

echo.
echo Copying APKs to release folder...

set "APK_DIR=app\build\outputs\apk"

if exist "%APK_DIR%\universal\release\app-universal-release.apk" (
    copy /Y "%APK_DIR%\universal\release\app-universal-release.apk" "app\release\%RELEASE_PREFIX%-universal.apk" >nul
    for %%F in ("app\release\%RELEASE_PREFIX%-universal.apk") do echo   [OK] %%~nxF  [%%~zF bytes]
) else (
    echo   [!!] Universal APK not found
)

if exist "%APK_DIR%\arm64\release\app-arm64-release.apk" (
    copy /Y "%APK_DIR%\arm64\release\app-arm64-release.apk" "app\release\%RELEASE_PREFIX%-v8a-minsdk24.apk" >nul
    for %%F in ("app\release\%RELEASE_PREFIX%-v8a-minsdk24.apk") do echo   [OK] %%~nxF  [%%~zF bytes]
) else (
    echo   [!!] arm64-v8a APK not found
)

if exist "%APK_DIR%\arm32\release\app-arm32-release.apk" (
    copy /Y "%APK_DIR%\arm32\release\app-arm32-release.apk" "app\release\%RELEASE_PREFIX%-v7a-minsdk21.apk" >nul
    for %%F in ("app\release\%RELEASE_PREFIX%-v7a-minsdk21.apk") do echo   [OK] %%~nxF  [%%~zF bytes]
) else (
    echo   [!!] armeabi-v7a APK not found
)

echo.
echo === DONE ===
echo Output directory: app\release\
echo.
echo   %RELEASE_PREFIX%-universal.apk    - все архитектуры в одном APK
echo   %RELEASE_PREFIX%-v8a-minsdk24.apk - только 64-bit ARM
echo   %RELEASE_PREFIX%-v7a-minsdk21.apk - только 32-bit ARM

echo.
pause
