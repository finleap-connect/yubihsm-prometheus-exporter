FROM alpine:3.14.2

RUN apk add py3-cryptography py3-requests
RUN apk add py3-pip && pip install --no-cache-dir yubihsm[http]==2.1.0 prometheus-client==0.11.0 && apk del py3-pip

COPY main.py /app/

EXPOSE 8080

ENTRYPOINT ["python3", "/app/main.py"]

