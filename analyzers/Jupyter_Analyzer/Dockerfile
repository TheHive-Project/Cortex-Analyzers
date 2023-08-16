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



FROM python:3.9
WORKDIR /worker
COPY . Jupyter_Analyzer
RUN test ! -e Jupyter_Analyzer/requirements.txt || pip install --no-cache-dir -rJupyter_Analyzer/requirements.txt
COPY <<-"EOT" /Jupyter_Analyzer/papermill_iorw.patch
--- iorw.py       2023-08-11 05:49:49.302149767 +0000
+++ iorw.py     2023-08-11 05:48:38.553642098 +0000
@@ -180,7 +180,7 @@
 class HttpHandler(object):
     @classmethod
     def read(cls, path):
-        return requests.get(path, headers={'Accept': 'application/json'}).text
+        return json.dumps(requests.get(path, headers={'Accept': 'application/json'}).json()["content"])
 
     @classmethod
     def listdir(cls, path):
@@ -188,7 +188,9 @@
 
     @classmethod
     def write(cls, buf, path):
-        result = requests.put(path, json=json.loads(buf))
+        payload = {"type": "notebook", "format": "json", "path": path}
+        payload["content"] = json.loads(buf)
+        result = requests.put(path, json=payload)
         result.raise_for_status()
 
     @classmethod
EOT
RUN pip install papermill
RUN apt update
RUN apt install patch
RUN patch $(python3 -c "from papermill import iorw; print(iorw.__file__)") /Jupyter_Analyzer/papermill_iorw.patch 
ENTRYPOINT Jupyter_Analyzer/jupyter.py


