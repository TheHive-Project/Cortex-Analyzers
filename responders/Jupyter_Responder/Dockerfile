FROM python:3-slim
WORKDIR /worker
COPY . Jupyter_Responder
RUN test ! -e Jupyter_Responder/requirements.txt || pip install --no-cache-dir -r Jupyter_Responder/requirements.txt

RUN apt update &&\
     apt install patch &&\
     patch $(python3 -c "from papermill import iorw; print(iorw.__file__)") Jupyter_Responder/papermill_iorw.patch 
ENTRYPOINT ["python", "Jupyter_Responder/jupyter.py"]
