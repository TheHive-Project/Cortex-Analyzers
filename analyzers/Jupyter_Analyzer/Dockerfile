# syntax=docker/dockerfile:1.3-labs
FROM python:3.9
WORKDIR /worker
COPY . Jupyter_Analyzer
RUN test ! -e Jupyter_Analyzer/requirements.txt || pip install --no-cache-dir -rJupyter_Analyzer/requirements.txt
RUN cat  <<EOF >/Jupyter_Analyzer/papermill_iorw.patch
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
EOF


RUN pip install papermill
RUN apt update
RUN apt install patch
RUN patch $(python3 -c "from papermill import iorw; print(iorw.__file__)") /Jupyter_Analyzer/papermill_iorw.patch 
ENTRYPOINT Jupyter_Analyzer/jupyter.py


