@echo off
chcp 65001 >nul 2>&1
setlocal
set "SRC=%~dp0out\PSLS.sys"
set "DST=C:\Windows\System32\drivers\PSLS.sys"
set "BAK=C:\Windows\System32\drivers\PSLS.sys.bak_clrfix"

net session >nul 2>&1
if errorlevel 1 (
    echo MUST_RUN_AS_ADMIN
    pause
    exit /b 1
)

echo --- 1) unload current driver ---
fltmc unload PSLS 2>nul
sc stop PSLS >nul 2>&1
sc query PSLS | findstr /i "STATE"

echo --- 2) backup and copy new build ---
if not exist "%BAK%" (
    copy /y "%DST%" "%BAK%" >nul && echo backed up: %BAK%
) else (
    echo backup already exists: %BAK%
)
copy /y "%SRC%" "%DST%"
if errorlevel 1 (
    echo COPY_FAILED
    pause
    exit /b 1
)

echo --- 3) load new driver ---
sc start PSLS
if errorlevel 1 (
    echo LOAD_FAILED_577_MEANS_SIGNATURE_REJECTED
    echo restoring previous driver...
    copy /y "%BAK%" "%DST%" >nul
    pause
    exit /b 1
)

echo --- 4) verify attached ---
fltmc filters | findstr /i psls
sc query PSLS | findstr /i "STATE"

echo --- 5) CLR regression probe (powershell is a CLR host, no modal dialog) ---
set "PROBE="
for /f "delims=" %%i in ('powershell -NoProfile -Command "Write-Output CLRPROBE_OK" 2^>^&1') do set "PROBE=%%i"
echo probe output: %PROBE%
echo %PROBE% | findstr /c:"CLRPROBE_OK" >nul
if errorlevel 1 goto :clr_broken

echo.
echo RESULT: CLR_OK - driver fix verified
goto :done

:clr_broken
echo.
echo RESULT: CLR_STILL_BROKEN - rolling back
fltmc unload PSLS 2>nul
sc stop PSLS >nul 2>&1
copy /y "%BAK%" "%DST%" >nul
echo rolled back to previous driver

:done
echo.
pause