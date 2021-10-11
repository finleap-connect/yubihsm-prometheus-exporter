ARG YUBI_HSM_VERSION=2.1.0
ARG PROMETHEUS_CLIENT_VERSION=0.11
ARG ALPINE_VERSION=3.14.2

FROM alpine:$ALPINE_VERSION as test

ARG YUBI_HSM_VERSION
ARG PROMETHEUS_CLIENT_VERSION

ARG TEST_YUBIHSM_CONNECTOR
ARG TEST_YUBIHSM_AUDIT_KEY_PIN
ARG TEST_YUBIHSM_APP_KEY_PIN
ARG TEST_YUBIHSM_AUDIT_KEY_ID="6"
ARG TEST_YUBIHSM_APP_KEY_ID="3"
ARG TEST_KEY_LABEL="vault-hsm-key"
ARG TEST_PORT="8080"

RUN apk add py3-cryptography py3-requests
RUN apk add py3-pip && pip install --no-cache-dir \
    yubihsm[http]==$YUBI_HSM_VERSION \
    prometheus-client==$PROMETHEUS_CLIENT_VERSION \
    pytest pytest-cov pylint \
    && apk del py3-pip

COPY *.py /test/
WORKDIR /test

RUN pytest --cov=. test_main.py
RUN if [ ! -z "$TEST_YUBIHSM_CONNECTOR" ]; then pytest system_test.py; fi

FROM alpine:$ALPINE_VERSION

ARG YUBI_HSM_VERSION
ARG PROMETHEUS_CLIENT_VERSION

RUN apk add py3-cryptography py3-requests
RUN apk add py3-pip && pip install --no-cache-dir \
    yubihsm[http]==$YUBI_HSM_VERSION \
    prometheus-client==$PROMETHEUS_CLIENT_VERSION \
    && apk del py3-pip

COPY main.py /app/

EXPOSE 8080

ENTRYPOINT ["python3", "/app/main.py"]

