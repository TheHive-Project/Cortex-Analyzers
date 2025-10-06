#!/bin/bash


# this program is for test only. To ensure the documentation is generated as it should.
# this program should be run from Cortex-Analyzers/ path only.
ROOT_PATH=${PWD}
TEST_PATH="./test_doc"

mkdir ${TEST_PATH}
for I in analyzers responders assets images AUTHORS AUTHORS docs *.md ; do cp -rv $I ${TEST_PATH} ; done
cd ${TEST_PATH}
gh repo clone TheHive-Project/doc-builder
#cp -rv ../../doc-builder . 

doc-builder/build/Cortex-Neurons/generate.py

cp -v CHANGELOG.md docs/.
cp -v code_of_conduct.md docs/.
cp -rv README.md docs/
cp -rv SECURITY.md docs/
cp -rv AUTHORS docs/AUTHORS.md

mkdocs serve -a 0.0.0.0:8889

cd ${ROOT_PATH}
rm -rf ${TEST_PATH}
