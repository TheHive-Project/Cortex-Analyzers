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

FROM python:3-slim
WORKDIR /worker
RUN apt update
RUN apt install -y wkhtmltopdf python3-magic
COPY requirements.txt EmlParser/
RUN test ! -e EmlParser/requirements.txt || pip install --no-cache-dir -r EmlParser/requirements.txt
COPY . EmlParser/
ENTRYPOINT ["python", "EmlParser/parse.py"]