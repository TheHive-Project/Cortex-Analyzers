#!/bin/bash
# This script downloads all available Virusshare.com hash files using curl and wget. It can be called as: ./getHashes.sh PATH


display_usage() { 
    echo "getHashes v0.2"
    echo "  Fetch all Virusshare.com hashes" 
    echo -e "\n  Usage: $0 <path> \n"
} 

if [  $# -ne 1 ]; then 
    display_usage
    exit 1
fi

if [ ! -d $1 ]; then
    display_usage
    echo -e "    Error: Directory not found: '$1'\n\n    :'(\n\n"
    exit 1

fi

cd $1
for u in `curl https://virusshare.com/hashes.4n6 | grep -E "VirusShare_[0-9]{5}\.md5" | c\
ut -d\" -f2 | cut -d\/ -f2`
do
    echo $u
    if [ -e $1/$u ]; then
        echo "File already downloaded"
    else
        wget https://virusshare.com/hashes/$u
        sleep 3
    fi

done | tee -a ../$0.log
cd ..
