# Dockerize you custom Analyzers & Responders

## Cortex-Analyzers catalogs
Since Cortex version 3.0, Analyzers and Responders can be executed as docker containers, and this is useful in several ways. The first is you do not have to bother with libraries and dependancies to run the program ; download the image, run it, trash it.  
We provide up-to-date docker images for all programs publicly available on our repository (https://github.com/TheHive-Project/Cortex-Analyzers). To use them, you just need to specify the catalog in the `application.conf` file for Cortex: 

```json
analyzer {
  urls = [
         "https://download.thehive-project.org/analyzers.json"
        ]
```

## What if you use custom and private Analyzers and Responders ? 
If you are using you own programs and want them to be processed as docker container, you can. You need to: 
- Build your images
- Build your catalog
- Register you catalog in Cortex

### Build your images
You need to build your docker image for each Analyzer/Responder. Ours are built with this *Dockerfile*  template except if a *Dockerfile* is present in the folder: 

```dockerfile
FROM python:3-alpine
WORKDIR /worker
COPY requirements.txt {worker_name}/
RUN test ! -e {worker_name}/requirements.txt || pip install --no-cache-dir -r {worker_name}/requirements.txt
COPY . {worker_name}/
ENTRYPOINT ["python", "{command}"]
```

*update variables accordingly*

This file is also in the repository: [Cortex-Analyzers/Dockerfile_template at master · TheHive-Project/Cortex-Analyzers · GitHub](https://github.com/TheHive-Project/Cortex-Analyzers/blob/master/utils/docker/Dockerfile_template)

### Build your catalog
A catalog is required for Analyzers and Responders. A catalog is a list of flavor definitions (typically the json definition of the flavor) and for each of them the *dockerImage* attribute is added with the name of the associated image. 
This catalog, when registered in Cortex's configuration file, allows the discovery of the available Analyzers or Responders and tells Cortex how to run each worker using the dockerImage attribute. Below is an example of a catalog file that contains a single Analyzer:


```json

[
{
  "name": "DShield_lookup",
  "version": "1.0",
  "author": "Xavier Xavier, SANS ISC",
  "url": "https://github.com/xme/thehive/Cortex-Analyzers",
  "license": "AGPL-V3",
  "description": "Query the SANS ISC DShield API to check for an IP address reputation.",
  "dataTypeList": [
    "ip"
  ],
  "baseConfig": "DShield",
  "config": {
    "service": "query"
  },
  "registration_required": false,
  "subscription_required": false,
  "free_subscription": true,
  "service_homepage": "https://isc.sans.edu/",
  "service_logo": {
    "path": "assets/dshield.png",
    "caption": "logo"
  },
  "screenshots": [
    {
      "path": "assets/long_report.png",
      "caption": "DShield: long report"
    }
  ],
  "dockerImage": "cortexneurons/dshield_lookup:1.0"
}
]
```

### Register your catalogs in Cortex configuration
Update your Cortex configuration file (`/etc/cortex/application.conf`) with your own catalog; e.g. for *Analyzers*:  

```yml
analyzer {
  urls = [
         "https://download.thehive-project.org/analyzers.json"
         "/opt/Custom-Analyzers/analyzers/analyzers.json"
        ]
```


Then restart Cortex.

###  build.sh
This program allows you to build your own images  ~AND~ catalogs. This program assumes your folder of custom *Analyzers* and *Responders* are respectively stored in *analyzers* and *responders* folders.

```
Custom-Analyzers
├── analyzers/
│   └── My_custom_analyzer/
└── responders/
    └── My_custom_responder/
        ├── customresponderflavor.json
        ├── Dockerfile
        ├── program.py*
        ├── README.md
        └── requirements.txt
```

To use it, update the variable `DOCKER_REPOSITORY` first (for example with the name of your team). Enter the folder of your own programs, amd and run it.

```bash
cd ./Custom-Analyzers
bash /path/to/build.sh 
```

Once finished, you should find your docker images built, and catalogs as well in `./analyzers/analyzers.json` and  `./responders/responders.json`.


```bash
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
FROM python:3
WORKDIR /worker
ARG workername
ARG command
COPY . \$workername
RUN test ! -e \$workername/requirements.txt || pip install --no-cache-dir -r \$workername/requirements.txt
ENTRYPOINT \$command
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
```
