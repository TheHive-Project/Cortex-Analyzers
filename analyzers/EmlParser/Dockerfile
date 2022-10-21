## To test an Analyzer of Responder with docker: 
#
# Copy this file in the folder of an analyzer or a responder and name it Dockerfile
## edit it and Change variables
#
# - {workername} by the folder name of the analyzer or responder
# - {command} by the value of the `command` in a JSON file
# 
# Save and run: 
#
# docker build -t cortexneurons/{flavor_name}:devel  with {flavor_name} the name of the analyzer of responder in the JSON file
#
# 



FROM python:3.9-slim
WORKDIR /worker
COPY . EmlParser
RUN test ! -e EmlParser/requirements.txt || pip install --no-cache-dir -rEmlParser/requirements.txt
RUN apt update
RUN apt install -y wkhtmltopdf libmagic1
ENTRYPOINT EmlParser/parse.py
