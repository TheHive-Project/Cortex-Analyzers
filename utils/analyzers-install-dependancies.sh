#!/bin/bash

for I in $(find AdamMcHugh-Cortex-Analyzers -name 'requirements.txt'); do sudo -H pip2 install -r $I; done
for I in $(find AdamMcHugh-Cortex-Analyzers -name 'requirements.txt'); do sudo -H pip3 install -r $I; done
