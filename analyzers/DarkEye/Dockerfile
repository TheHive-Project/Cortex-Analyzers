FROM python:3-slim
WORKDIR /worker
COPY requirements.txt DarkEye/
RUN pip install --no-cache-dir -r DarkEye/requirements.txt
COPY . DarkEye/
ENTRYPOINT ["python", "DarkEye/darkeye.py"]
