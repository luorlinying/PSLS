@echo off
chcp 65001 >nul 2>&1
setlocal
cd /d "%~dp0"

rem 通过环境变量覆盖，或自动定位最新 Visual Studio 的 vcvars64.bat
if not defined VS_VCVARS (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
    if defined VSDIR set "VS_VCVARS=%VSDIR%\VC\Auxiliary\Build\vcvars64.bat"
)

if not defined VS_VCVARS (
    echo VCVARS_NOT_SET
    echo 请先设置 VS_VCVARS 指向 vcvars64.bat，例如：
    echo   set "VS_VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    exit /b 1
)

call "%VS_VCVARS%"
if errorlevel 1 (
    echo VCVARS_FAILED
    exit /b 1
)

if not defined WDK_ROOT set "WDK_ROOT=C:\Program Files (x86)\Windows Kits\10"

echo --- running scons ---
python -m SCons
set RC=%ERRORLEVEL%
echo.
echo SCONS_EXIT=%RC%
if exist "out\PSLS.sys" (
    echo OUT_SYS_PRESENT
    dir /b "out\PSLS.sys"
) else (
    echo OUT_SYS_MISSING
)
exit /b %RC%
