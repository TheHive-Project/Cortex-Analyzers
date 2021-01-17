#!/bin/bash

# this program is for test only. To ensure the documentation is generated as it should.
# this program should be run from Cortex-Analyzers/ path only.

gh repo clone TheHive-Project/doc-builder

doc-buidler/build/Cortex-Neurons/generate.py

cp -v CHANGELOG.md docs/.
cp -v code_of_conduct.md docs/.
cp -rv images docs/
cp -rv README.md docs/


