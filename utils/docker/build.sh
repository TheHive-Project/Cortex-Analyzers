#!/usr/bin/env bash

###
# This program assumes your analyzers and responders folder looks like: 
#
#     Custom-Analyzers
#     ├── analyzers/
#     │   └── My_custom_analyzer/
#     └── responders/
#         └── My_custom_responder/
#             ├── customresponderflavor.json
#             ├── Dockerfile
#             ├── program.py*
#             ├── README.md
#             └── requirements.txt
#
# Usage: 
# Update DOCKER_REPOSITORY variable
# cd ./Custom-Analyzers
# bash /path/to/build.sh 
###

# Set your docker repository name
DOCKER_REPOSITORY=ilovestrangebee

build_image() {
      JSON=$1
    cat << EOF > /tmp/default_dockerfile
FROM python:3-alpine
ARG workername
ARG command
WORKDIR /worker
COPY requirements.txt \$workername/
RUN test ! -e \$workername/requirements.txt || pip install --no-cache-dir -r \$workername/requirements.txt
COPY . \$workername/
ENTRYPOINT ["python","\$command"]
EOF

    DEFAULT_DOCKERFILE=/tmp/default_dockerfile
      TAG=`cat ${JSON} | jq -r '( "'"$DOCKER_REPOSITORY"'" + "/" + (.name | ascii_downcase) + ":" + (.version))'`
    WORKER_NAME=`cat ${JSON} | jq -r '(.version)'`  
    COMMAND=`cat ${JSON} | jq -r '(.command)'`
    DIRNAME=`dirname ${JSON}`
      WORKER_NAME=`basename ${DIRNAME}`
    if test -f ${DIRNAME}/Dockerfile
    then
          docker build -t ${TAG} `dirname ${JSON}`
    else
          docker build --build-arg workername=${WORKER_NAME} --build-arg command=${COMMAND} -f ${DEFAULT_DOCKERFILE} -t ${TAG} `dirname ${JSON}`
    fi
}

build_catalog() {
    DIR=$1
    echo '[' > ${DIR}/${DIR}.json


    first=1
    for JSON in ${DIR}/*/*.json
    do
          build_image ${JSON} 
        if test -z "${first}"
        then
              echo ',' >> ${DIR}/${DIR}.json
        else
              first=
        fi  
        jq 'del(.command) + { dockerImage: ("'"$DOCKER_REPOSITORY"'" + "/" + (.name | ascii_downcase) + ":" + (.version)) }' ${JSON} >> ${DIR}/${DIR}.json
    done

    echo ']' >> ${DIR}/${DIR}.json
}

build_catalog analyzers
build_catalog responders
