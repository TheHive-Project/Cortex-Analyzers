#!/bin/bash

# This program is for test purposes only, to ensure the documentation is generated as expected.
# This program should be run from the Cortex-Analyzers/ path only.

ROOT_PATH="${PWD}"
TEST_PATH="./test_doc"
VENV_PATH="${ROOT_PATH}/venv"
REQUIREMENTS_FILE="${ROOT_PATH}/utils/test_doc/requirements.txt"

# Cleanup function
cleanup() {
  echo "Cleaning up temporary files..."
  deactivate 2>/dev/null
  cd "${ROOT_PATH}" || exit
  rm -rf "${TEST_PATH}"
}
trap 'cleanup' EXIT

# Create the test documentation path
mkdir -p "${TEST_PATH}"

# Copy necessary directories and files
for I in analyzers responders assets images AUTHORS docs *.md; do
  cp -rv "$I" "${TEST_PATH}"
done

cd "${TEST_PATH}" || exit

# Create a Python virtual environment if not already created
if [ ! -d "$VENV_PATH" ]; then
  echo "Creating virtual environment..."
  python3 -m venv "$VENV_PATH"
fi

# Activate the virtual environment
source "${VENV_PATH}/bin/activate"

# Ensure pip is updated
pip install --upgrade pip

# Check and install dependencies from requirements.txt
if [ -f "$REQUIREMENTS_FILE" ]; then
  echo "Installing dependencies from $REQUIREMENTS_FILE..."
  pip install -r "$REQUIREMENTS_FILE"
else
  echo "Error: $REQUIREMENTS_FILE not found!"
  deactivate
  exit 1
fi

# Clone the repository if not already cloned
if [ ! -d "doc-builder" ]; then
  gh repo clone TheHive-Project/doc-builder
fi

# Execute the generate script
python doc-builder/build/Cortex-Neurons/generate.py

# Copy specific files to the docs folder
cp -v CHANGELOG.md docs/.
cp -v code_of_conduct.md docs/.
cp -v README.md docs/
cp -v SECURITY.md docs/
cp -v AUTHORS docs/AUTHORS.md

# Serve documentation with mkdocs
mkdocs serve -a 0.0.0.0:8889

echo "Script execution completed!"
