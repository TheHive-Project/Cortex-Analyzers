#!/usr/bin/env bash

build_catalog() {
    DIR=$1
    echo '[' > ${DIR}/catalog.json
    echo '[' > ${DIR}/catalog-devel.json
    echo '[' > ${DIR}/catalog-stable.json

    first=1
    for JSON in ${DIR}/*/*.json
    do
        if test -z "${first}"
        then
    	echo ',' >> ${DIR}/catalog.json
    	echo ',' >> ${DIR}/catalog-devel.json
    	echo ',' >> ${DIR}/catalog-stable.json
        else
    	first=
        fi

        jq 'del(.command) + { dockerImage: ("cortexneurons/" + (.name | ascii_downcase) + ":devel") }' ${JSON} >> ${DIR}/catalog-devel.json
        jq 'del(.command) + { dockerImage: ("cortexneurons/" + (.name | ascii_downcase) + ":" + .version) }' ${JSON} >> ${DIR}/catalog-stable.json
        jq 'del(.command) + { dockerImage: ("cortexneurons/" + (.name | ascii_downcase) + ":" + (.version | split("."))[0]) }' ${JSON} >> ${DIR}/catalog.json
    done

    echo ']' >> ${DIR}/catalog.json
    echo ']' >> ${DIR}/catalog-devel.json
    echo ']' >> ${DIR}/catalog-stable.json
}

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

build_catalog ${BASE_DIR}/analyzers
build_catalog ${BASE_DIR}/responders
