@echo off
setlocal

set "GHIDRA_PATH=C:\ghidra_11.1.2"

set "PROJECT_PATH=%cd%"
set "PROJECT_NAME=LATTE_Project"


set "GHIDRA_EXPORT_PATH=%TEMP%\ghidra_export.json"

if "%~1"=="" (
    echo Usage: %0 ^<path_to_binary^>
    goto :eof
)
set "TARGET_BINARY=%~1"

echo Step 1: Running Ghidra Extractor on %TARGET_BINARY%...


"%GHIDRA_PATH%\support\analyzeHeadless.bat" "%PROJECT_PATH%" %PROJECT_NAME% -import "%TARGET_BINARY%" -postscript LATTE_extractor.py -deleteProject

echo Step 2: Running LATTE Analyzer...

python analyzer.py --input "%GHIDRA_EXPORT_PATH%"

echo Analysis Complete.

endlocal