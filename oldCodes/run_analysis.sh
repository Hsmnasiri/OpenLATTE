
GHIDRA_PATH="/mnt/z/Ghidra/ghidra_11.3.1_PUBLIC_20250219/ghidra_11.3.1_PUBLIC"
PROJECT_PATH="./ghidra_projects"
PROJECT_NAME="LATTE_Project"
GHIDRA_EXPORT_PATH="./ghidra_export.json"
TARGET_BINARY=$1



#  Check if a binary file was provided as an argument
if [ -z "$TARGET_BINARY" ]; then
    echo "Usage: ./run_analysis.sh <path_to_binary>"
    exit 1
fi

# Check the Ghidra path is configured correctly
if [ ! -f "$GHIDRA_PATH/support/analyzeHeadless" ]; then
    echo "ERROR: Ghidra not found at '$GHIDRA_PATH'."
    echo "Please edit run_analysis.sh and set the GHIDRA_PATH variable."
    exit 1
fi

# Clean up old project/export files to ensure a fresh run
rm -rf "$PROJECT_PATH/$PROJECT_NAME.gpr" "$PROJECT_PATH/$PROJECT_NAME.rep"
rm -f "$GHIDRA_EXPORT_PATH"

echo "Step 1: Running Ghidra Extractor on $TARGET_BINARY..."

# Run the Ghidra headless analyzer to extract data
"$GHIDRA_PATH/support/analyzeHeadless" "$PROJECT_PATH" $PROJECT_NAME \
    -import "$TARGET_BINARY" \
    -postscript "$(pwd)/LATTE_extractor.py" \
    -deleteProject

# Check if the export file was created by Ghidra
if [ ! -f "$GHIDRA_EXPORT_PATH" ]; then
    echo "ERROR: Ghidra analysis failed. The export file was not created."
    echo "Check for errors in the Ghidra output above."
    exit 1
fi

echo "Step 2: Running LATTE Analyzer..."

# Run the main Python analysis script
python3 analyzer.py --input "$GHIDRA_EXPORT_PATH"

echo "Analysis Complete."