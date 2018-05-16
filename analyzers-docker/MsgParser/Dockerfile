FROM cortex-base-python2
ADD ./analyzers/MsgParser /analyzer
WORKDIR /analyzer
RUN pip install --no-cache-dir -r requirements.txt
CMD ./parse.py
