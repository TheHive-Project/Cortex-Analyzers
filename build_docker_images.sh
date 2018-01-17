#!/usr/bin/env bash
# Vars
VER=1.0.0

# Docker base images
echo "Building base images..."
docker build -t cortex-base-python2:$VER contrib/docker/cortex-base-python2
docker build -t cortex-base-python2:latest contrib/docker/cortex-base-python2
docker build -t cortex-base-python3:$VER contrib/docker/cortex-base-python3
docker build -t cortex-base-python3:latest contrib/docker/cortex-base-python3

echo "Building analyzer images..."
for analyzer in `ls -1 analyzers/|grep -v File_Info`; do
  lower=`echo ${analyzer} | tr "[:upper:]" "[:lower:]"`
  echo "Building cortex-analyzers-$lower"
  OUTPUT=$(docker build -t cortex-analyzers-${lower} -f analyzers-docker/${analyzer}/Dockerfile .)
  if [ $? != 0 ]; then
    echo -e "\e[91m$OUTPUT\e[0m"
    echo -e "\e[100m\e[91mError while building image for $analyzer.\e[0m"
    exit 1
  fi
done
echo -e "\e[100m\e[92mSuccessfully built analyzer docker images. Check them via 'docker image ls'.\e[0m"

