#!/usr/bin/env bash
# Vars
VER=1.0.0
PREFIX=$1

# Docker base images
echo "Building base images..."
if [ ! ${PREFIX} = "" ]; then
  docker build -t ${PREFIX}/cortex-base-python2:${VER} --build-arg VERSION=${VER} --build-arg BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"` --build-arg VCS_REF=`git rev-parse --short HEAD` contrib/docker/cortex-base-python2
  docker build -t ${PREFIX}/cortex-base-python2:latest --build-arg VERSION=${VER} --build-arg BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"` --build-arg VCS_REF=`git rev-parse --short HEAD` contrib/docker/cortex-base-python2
  docker build -t ${PREFIX}/cortex-base-python3:${VER} --build-arg VERSION=${VER} --build-arg BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"` --build-arg VCS_REF=`git rev-parse --short HEAD` contrib/docker/cortex-base-python3
  docker build -t ${PREFIX}/cortex-base-python3:latest --build-arg VERSION=${VER} --build-arg BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"` --build-arg VCS_REF=`git rev-parse --short HEAD` contrib/docker/cortex-base-python3
else
  docker build -t cortex-base-python2:${VER} --build-arg VERSION=${VER} --build-arg BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"` --build-arg VCS_REF=`git rev-parse --short HEAD` contrib/docker/cortex-base-python2
  docker build -t cortex-base-python2:latest --build-arg VERSION=${VER} --build-arg BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"` --build-arg VCS_REF=`git rev-parse --short HEAD` contrib/docker/cortex-base-python2
  docker build -t cortex-base-python3:${VER} --build-arg VERSION=${VER} --build-arg BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"` --build-arg VCS_REF=`git rev-parse --short HEAD` contrib/docker/cortex-base-python3
  docker build -t cortex-base-python3:latest --build-arg VERSION=${VER} --build-arg BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"` --build-arg VCS_REF=`git rev-parse --short HEAD` contrib/docker/cortex-base-python3
fi

echo "Building analyzer images..."
for analyzer in `ls -1 analyzers/|grep -v File_Info`; do
  lower=`echo ${analyzer} | tr "[:upper:]" "[:lower:]"`
  echo "Building cortex-analyzers-$lower"
  if [ ! ${PREFIX} = "" ]; then
    OUTPUT=$(docker build -t ${PREFIX}/cortex-analyzers-${lower} -f analyzers-docker/${analyzer}/Dockerfile .)
  else
    OUTPUT=$(docker build -t cortex-analyzers-${lower} -f analyzers-docker/${analyzer}/Dockerfile .)
  fi
  if [ $? != 0 ]; then
    echo -e "\e[91m$OUTPUT\e[0m"
    echo -e "\e[100m\e[91mError while building image for $analyzer.\e[0m"
    exit 1
  fi
done
echo -e "\e[100m\e[92mSuccessfully built analyzer docker images. Check them via 'docker image ls'.\e[0m"

