#!/bin/bash
# This script downloads all available Virusshare.com hash files using curl and wget. It can be called as: ./getHashes.sh PATH


display_usage() { 
    echo "getHashes v0.3"
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

WD=$1
declare -a base_urls=($(printf 'url=https://virusshare.com/hashfiles/%0.s\n' {1..1}))
declare -a base_outs=($(printf 'output=./%0.s\n' {1..1}))

pushd $WD
while mapfile -t -n 8 ary && ((${#ary[@]}));
do
  rm -f ../config
  IFS=,
  eval echo "${base_urls[*]}"{"${ary[*]}"} | tr " " "\n" >> ../config
  eval echo "${base_outs[*]}"{"${ary[*]}"} | tr " " "\n" >> ../config
  curl -s -N --parallel --parallel-immediate --parallel-max 8 --config config | tee -a ../$0.log
  sleep 3
done <<< `curl -s -L https://virusshare.com/hashes.4n6 | grep -E "VirusShare_[0-9]{5}\.md5" | cut -d\" -f2 | cut -d\/ -f2`
popd

