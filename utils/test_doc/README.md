# Cortex-Neurons local documentation preview

This script renders the Cortex-Neurons documentation locally.

## Usage

1. Run the script from root directory Cortex-Analyzers
```bash
bash utils/test_doc/testdoc-venv.sh
```

2. View the documentation at http://0.0.0.0:8889

## Script Overview
The script performs the following actions:

- Creates a test environment for documentation in a temporary folder.
- Copies necessary files and directories into the temporary folder.
- Sets up a Python virtual environment and installs dependencies from requirements.txt.
- Clones the doc-builder repository from GitHub if not already cloned.
- Runs the documentation generation script.
- Serves the generated documentation using MkDocs.
- Cleans up temporary files upon completion.

## Notes
Ensure the script is ran from the root directory of the Cortex-Analyzers repository.