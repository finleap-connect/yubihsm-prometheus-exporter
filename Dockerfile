FROM alpine:3.14.2

RUN apk add py3-pip py3-cryptography
RUN pip install --no-cache-dir yubihsm==2.1.0 prometheus-client==0.11.0

COPY main.py /app/

EXPOSE 8080

ENTRYPOINT ["python3", "/app/main.py"]

