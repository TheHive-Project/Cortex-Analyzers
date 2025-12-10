#!/bin/bash


# Build and manage your own docker images of Analyzers or Responders:
# - Build your custom docker images
# - Store related Analyzer or Responder definition file in your dedicated custom folders
# - Archive your docker images in a dedicated folder
# - Use a custom image repository (See VARIABLES TO CUSTOMISE)


############################
#  REQUIREMENTS            #
############################ 
# - jq (from https://stedolan.github.io/jq/ - ex: `apt install jq`)
# - json-spec (`pip3 install json-spec`)
# - python3 + json lib
 

######### 
# USAGE #
#########
# $ bash utils/docker/build-customimage.sh -t TYPE -b DEFINITION_FILE
# with:
# -t : type of neurons (analyzer or responder)
# -b : path to analyzer or responder description file
# 
# Example: 
# $ cd /opt/Cortex-Analyzers
# $ bash utils/docker/build-customimage.sh -t analyzer -b analyzers/EmlParser/EmlParser.json



#############################
#  VARIABLES TO CUSTOMISE   #
############################# 
## Set the path for custom analyzers (configured in Cortex)
analyzerspath="/opt/customneurons/analyzers"
## Set the path to your custom responders repository  (configured in Cortex)
responderspath="/opt/customneurons/responders"
# Set the path to your docker images archives
dockerimagearchives="/opt/backup-images"
# Set a name for the docker image registry 
dockerimageregistryname="localhost"
# Set a name for the docker image repository 
dockerimagerepositoryname="customimages"

###################################
# HOW TO  RELOAD DOCKERIMAGES     #
###################################
#
# for I in `ls "${dockerimagearchives}/${dockerimagerepositoryname}-*.tar`; do docker load < $I ; done 
#


############################
#  PROGRAM VARIABLES       #
############################ 
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
LOGFILE="/tmp/build-customimage.log"

##############################
#  NEURON SCHEMA DESCRIPTION #
##############################
neuronschema='{
    "type": "object",
    "properties": {
        "name": {
            "type": "string"
        },
        "version": {
            "type": "string"
        },
        "author": {
            "type": "string"
        },
        "url": {
            "type": "string",
            "format": "uri"
        },
        "license": {
            "type": "string"
        },
        "description": {
            "type": "string"
        },
        "dataTypeList": {
            "type": "array"
        },
        "command": {
            "type": "string"
        },
        "baseConfig": {
            "type": "string"
        },
        "config": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string"
                }
            }
        },
        "configurationItems": {
            "type": "array",
            "items": {
                "$ref": "#/definition/configurationItem"
            }
        },
        "registration_required": {
            "type": [
                "boolean",
                "string"
            ]
        },
        "subscription_required": {
            "type": [
                "boolean",
                "string"
            ]
        },
        "free_subscription": {
            "type": [
                "boolean",
                "string"
            ]
        },
        "service_homepage": {
            "type": "string"
        },
        "service_logo": {
            "type": "object"
        },
        "screenshots": {
            "type": "array",
            "items": {
                "$ref": "#/definition/screenshot"
            }
        }
    },
    "required": [
        "name",
        "version",
        "author",
        "url",
        "license",
        "description",
        "dataTypeList",
        "command",
        "baseConfig"
    ],
    "definition": {
        "configurationItem": {
            "properties": {
                "name": {
                    "type": "string"
                },
                "description": {
                    "type": "string"
                },
                "type": {
                    "type": "string"
                },
                "multi": {
                    "type": "boolean"
                },
                "required": {
                    "type": "boolean"
                },
                "defaultValue": {
                    "type": ["string", "number","boolean", "array"]
                }
            },
            "required": [
                "name",
                "description",
                "multi",
                "required",
                "type"
            ]
        },
        "screenshot": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string"
                },
                "caption": {
                    "type": "string"
                }
            },
            "required": [
                "path",
                "caption"
            ]
        }
    }
}
'

############################
# MANAGE LOG FILE & OUTPUT #
############################
[[ -f ${LOGFILE} ]] && rm ${LOGFILE}
exec 3>$(tty)
exec 2>&1> ${LOGFILE}

display_info() {
  log message "Something went wrong. More information is available in ${LOGFILE} file."
}

log () {
  TYPE=$1
  MESSAGE=$2

  case $1 in
    "success" )
    TAG=""
    COLOR=${WHITE}
    ;;

    "ko" )
    TAG="[ERROR]: "
    COLOR=${RED}
    ;;

    "ok" )
    TAG="[INFO]: "
    COLOR=${BLUE}
    ;;

    "message" )
    TAG="[INFO]: "
    COLOR=${BLUE}
    ;;
    
  esac

  echo -e "${TAG}${MESSAGE}"
  echo -e "${COLOR}${TAG}${MESSAGE}${NC}" >&3
}

################
# HELP MESSAGE #
################
display-help()
{
   # Display Help
  HELP="Build docker images for Custom analyzers and responders
  
   Syntax: $0 [options]
   
   options:
   -h          Print this Help.
   -t type     Type: 'analyzer' or 'responder' 
   -b path     Path of analyzer or responder json file
   "
  
  log success "${HELP}"
}


##########################################
# CHECK TYPE AND RETURN DESTINATION PATH # 
# FOR THE UPDATED JSON FILE              #
##########################################
neuron-type() {
  type=$1

  if [ "${type}" = "analyzer" ] || [ "${type}" = "responder" ]
  then
    [[ "${type}" = "analyzer" ]] && destinationpath=${analyzerspath}
    [[ "${type}" = "responder" ]] && destinationpath=${responderspath}
  else
   log ko "neuron type can be 'analyzer' or 'responder'"
    exit 1
  fi
}

############################
# VALIDATE JSON FORMAT     #
############################
json-validate() {
  jsondata=$1
  cat ${jsondata} | python3 -mjson.tool > /dev/null && log ok "JSON validated" 
}


############################
# VALIDATE JSON SCHEMA     #
############################
validate-json-schema() {
  jsonfile=$1
  (json validate --schema-json="${neuronschema}" --document-file=${jsonfile} && log ok "JSON schema validated") || (log ko "JSON schema is invalid. Check logs in /tmp/build-customimage.log" && exit 1)
}

#########################################
# UPDATE JSON FILE WITH dockerImage     #
#########################################
updatejsonfile() {
  sourcefile=$1
  dest=$2
  (
    cat ${sourcefile} | jq 'del(.command)'  | jq --arg j ${dockerimagename} '. + {dockerImage: $j }' > "${dest}"
  )

}

#########################################
# UPDATE PERMISSION ON JSON FILE        #
#########################################
updatepermissions() {
  destination=$1
  uid=$2
  gid=$3
  chown -R ${uid}:${gid} ${destination}
}

#########################################
# BUILD DOCKER FILE IF NOT EXIST        #
#########################################
builddockerfile() {
  dockerfile=$1
  workername=$2
  command=$3

  if [ -z "${dockerfile+x}" ] || [ -z "${workername+x}" ] || [ -z "${command+x}" ]
  then
    exit 1
  else
    echo "FROM python:3-alpine" > ${dockerfile}
    echo "WORKDIR /worker" >> ${dockerfile}
    echo "COPY . ${workername}" >> ${dockerfile}
    echo "RUN test ! -e ${workername}/requirements.txt || pip install --no-cache-dir -r ${workername}/requirements.txt" >> ${dockerfile}
    echo "ENTRYPOINT ${command}" >> ${dockerfile}
  fi
}

############################
#  DOCKER BUILD & SAVE     #
############################
docker-commands() {
  folderpath=$1
  dockerimagename=$2

  (
    cd ${folderpath} && \
    (
      (
      docker build -t ${dockerimagename} . && log ok "Docker image ${dockerimagename} build successfully" 
      ) || \
      (
        log ko "Docker build failed. See ${LOGFILE} for more information" && exit 1
      )
    ) && \
    ( docker save -o ${archivename} ${dockerimagename} && log ok "Image saved sucessfully in ${archivename}"
    )
  )
}

############################
#  BUILD IMAGE             #
############################
build-image() {
  jsonpath=$1
  folderpath=$(dirname ${jsonpath})
  neurontype=$2 
  if [ -d ${folderpath} ]
  then
    # Get name of the analyzer/responder
    if [ -f ${jsonpath} ]
    then
      json-validate ${jsonpath} && validate-json-schema ${jsonpath} && neuronname=$(cat ${jsonpath} | jq '.name' | tr  '[:upper:]'  '[:lower:]' | tr -d '"') 
    else
      log ko "JSON file does not exist"
      exit
    fi
    # Set docker image name
    dockerimagename="${dockerimageregistryname}/${dockerimagerepositoryname}/${neuronname}:latest"
    # Set docker image archive name
    archivename="${dockerimagearchives}/${dockerimagerepositoryname}-${neuronname}.tar"
    
    # if no Dockerfile, create a default one
    (
      [[ -f "${folderpath}/Dockerfile" ]] || \
      builddockerfile "${folderpath}/Dockerfile" ${workername} ${command}
    )
    
    # build and Save docker image
    docker-commands ${folderpath} ${dockerimagename}

    # Update and save json file with dockerImage value
    mkdir -p ${destinationpath}/${workername}
    updatejsonfile ${jsonpath} ${destinationpath}/${workername}/$(basename  ${jsonpath})
    updatepermissions ${destinationpath} $(stat -c '%u' ${destinationpath}) $(stat -c '%g' ${destinationpath})
    log success "\nDocker image for your ${neurontype} has been built successfully.
Image name: ${dockerimagename}
JSON file updated and saved in: ${destinationpath}/${workername}/$(basename  ${jsonpath})"

  else
    log ko "path does not exist"
    log ko "Specify the path with the source files of the analyzer/responder"
    exit 1
  fi
}


############################
#  GET OPTIONS AND RUN     #
############################
while getopts ":ht:b:" option; do
   case $option in

      h) # display Help
        display-help
        exit;;
      t) # define neuron type
        t=${OPTARG}
        ;;
      b) # build docker image. Specify json path
        b=${OPTARG}
        ;;
      \?) # Invalid option
        log ko "Invalid option ${OPTARG}"
        display-help
        exit 1;;
   esac
done

#####################################
#  ENSURE REQUIRED OPTIONS ARE SET  #
# AND RUN MAIN PROGRAMS             #
#####################################
run() {
  if [ -z "${t+x}" ] || [ -z "${b+x}" ] 
  then
    display-help
  else
    neuron-type ${t}
    build-image ${b} ${t}
  fi
}



run



exec 3>&-
