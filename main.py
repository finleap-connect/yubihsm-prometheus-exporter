#!/usr/bin/python3

import logging
import os
import json
import time
import signal
from cryptography.hazmat.primitives.asymmetric import padding

import yubihsm
import prometheus_client


SLEEP_TIME_BETWEEN_PROBES = 5


def expect_field(data, context, name, t):
    if name not in data or not isinstance(data[name], t):
        logging.error('Expected field %s of type %s in %s', name, t, context)
        exit(1)
    else:
        return data[name]


class YubiHSMConfiguration:

    @property
    def url(self):
        return self.__url

    @property
    def application_key_id(self):
        return self.__application_key_id

    @property
    def application_key_pin_path(self):
        return self.__application_key_pin_path

    @property
    def audit_key_id(self):
        return self.__audit_key_id

    @property
    def audit_key_pin_path(self):
        return self.__audit_key_pin_path

    @property
    def name(self):
        return self.__name

    @property
    def encryption_key_label(self):
        return self.__encryption_key_label

    def __init__(self, url, application_key_id=None, application_key_pin_path='',
                 audit_key_id=None, audit_key_pin_path='', name='',
                 encryption_key_label=None):
        self.__url = url
        self.__application_key_id = application_key_id
        self.__application_key_pin_path = application_key_pin_path
        self.__audit_key_id = audit_key_id
        self.__audit_key_pin_path = audit_key_pin_path
        self.__name = name
        self.__encryption_key_label = encryption_key_label

    @staticmethod
    def load_config(data):
        expect_field(data, 'connectors', 'url', str)
        if 'application_key_id' in data:
            expect_field(data, 'connectors', 'application_key_id', int)
            expect_field(data, 'connectors', 'application_key_pin_path', str)
            expect_field(data, 'connectors', 'encryption_key_label', str)
        if 'audit_key_id' in data:
            expect_field(data, 'connectors', 'audit_key_id', int)
            expect_field(data, 'connectors', 'audit_key_pin_path', str)
        return YubiHSMConfiguration(**data)


class Configuration:

    def __init__(self, connectors, metrics_port):
        self.__connectors = connectors
        self.__metrics_port = metrics_port

    @property
    def connectors(self):
        return self.__connectors

    @property
    def metrics_port(self):
        return self.__metrics_port

    @staticmethod
    def load_config(data):
        connectors = expect_field(data, '""', 'connectors', list)
        return Configuration(
                connectors=[YubiHSMConfiguration.load_config(c)
                            for c in connectors],
                metrics_port=data.get('metrics_port', 8080))


def load_configuration(path):
    with open(path) as config_file:
        data = json.load(config_file)
        return Configuration.load_config(data)


def version_to_string(version):
    return '%d.%d.%d' % version


def load_pin(path):
    try:
        with open(path) as file:
            return file.read().rstrip()
    except IOError as e:
        logging.error('Failed to read file %s: %s', path, e)
        exit(1)


class TestSecret:

    DEFAULT_SECRET='🐸'

    def __init__(self, secret=DEFAULT_SECRET):
        self.__secret = secret.encode('utf8')
        self.__encrypted = False

    @property
    def secret(self):
        return self.__secret.decode('utf8') if not self.__encrypted else self.__secret.hex()

    def get(self):
        return self.secret, self.__encrypted

    def process(self, encrypt, decrypt):
        if self.__encrypted:
            self.__secret = decrypt(self.__secret)
        else:
            self.__secret = encrypt(self.__secret)
        self.__encrypted = not self.__encrypted


class Metrics:

    def __init__(self):
        labels=["url", "name"]
        self.__info = prometheus_client.Info(
                'yubihsm_device', 'Information about YubiHSM2 device', labels)
        self.__log_size = prometheus_client.Gauge(
                'yubihsm_log_size', 'Number of log entry in YubiHSM', labels)
        self.__used_log_entries = prometheus_client.Gauge(
                'yubihsm_used_log_entries', 'Number of used log entries in YubiHSM',
                labels)
        self.__test_connections = prometheus_client.Counter(
                'yubihsm_test_connections', 'Number test connections to YubiHSM',
                labels)
        self.__test_errors = prometheus_client.Counter(
                'yubihsm_test_errors', 'Number of failed YubiHSM test runs',
                labels + ['error'])

    @property
    def info(self):
        return self.__info

    @property
    def log_size(self):
        return self.__log_size

    @property
    def used_log_entries(self):
        return self.__used_log_entries

    @property
    def test_connections(self):
        return self.__test_connections

    @property
    def test_errors(self):
        return self.__test_errors


class YubiHSMProbe:

    def __init__(self, config, test_secret, metrics):
        self.__config = config
        self.__labels = dict(url=self.__config.url,
                             name=self.__config.name)
        self.__metrics = metrics
        self.__previous_log_entry = None
        self.__test_secret = test_secret

    def retrieve_logs(self, hsm):
        try:
            session = hsm.create_session_derived(
                self.__config.audit_key_id,
                load_pin(self.__config.audit_key_pin_path))
            try:
                logs = session.get_log_entries()
                if logs:
                    for log in logs.entries:
                        logging.info(
                                'Log #%d from %s: %d with length %d on %d & %d => %d @%d, %d, Digest: %s', 
                                log.number, self.__config.url, log.command,
                                log.length, log.target_key, log.second_key,
                                log.result, log.tick, log.session_key, log.digest.hex())
                    try: # There might be multiple log fetchers in place
                        session.set_log_index(logs.entries[-1].number)
                    except yubihsm.exceptions.YubiHsmDeviceError as e:
                        pass
                logging.info('Retrieved logs successfully')
            finally:
                session.close()
        except yubihsm.exceptions.YubiHsmError as e:
            logging.error('Failed to retrieve logs from %s: %s, %s', 
                          self.__config.url, type(e).__name__, str(e))
            self.__metrics.test_errors.labels(**(self.__labels | {'error': 'get_logs'})).inc()

    def encryption_test(self, hsm):
        try:
            session = hsm.create_session_derived(
                self.__config.application_key_id,
                load_pin(self.__config.application_key_pin_path))
            try:
                key = session.list_objects(label=self.__config.encryption_key_label)
                if len(key) == 1:
                    key = key[0]
                    ef = lambda x: key.get_public_key().encrypt(x, padding.PKCS1v15())
                    df = lambda x: key.decrypt_pkcs1v1_5(x)
                    self.__test_secret.process(decrypt=df, encrypt=ef)
                    secret, encrypted = self.__test_secret.get()
                    logging.info(
                            '%s data with key from %s => %s',
                            'Encrypted' if encrypted else 'Decrypted', 
                            self.__config.url, secret)
                    if not encrypted and (secret != TestSecret.DEFAULT_SECRET):
                        logging.error(
                            'Decryption using %s returned wrong result %s, expected %s',
                            self.__config.url, secret, TestSecret.DEFAULT_SECRET)
                        raise yubihsm.exceptions.YubiHsmInvalidResponseError()
                else:
                    logging.error(
                            'Got None or to much objects with label %s from %s',
                            self.__config.encryption_key_label, self.__config.url)
                    raise yubihsm.exceptions.YubiHsmInvalidResponseError()
            finally:
                session.close()
        except yubihsm.exceptions.YubiHsmError as e:
            logging.error('Failed encryption test on %s: %s, %s', 
                          self.__config.url, type(e).__name__, str(e))
            self.__metrics.test_errors.labels(**(self.__labels | {'error': 'crypto_test'})).inc()

    def probe(self):
        logging.info('Connect to YubiHSM connector %s', self.__config.url)
        hsm = yubihsm.YubiHsm.connect(self.__config.url)
        try:
            self.__metrics.test_connections.labels(**self.__labels).inc()
            info = hsm.get_device_info()
            self.__metrics.info.labels(**self.__labels).info(
                    {'version': version_to_string(info.version),
                     'serial': str(info.serial)})
            self.__metrics.log_size.labels(**self.__labels).set(info.log_size)
            self.__metrics.used_log_entries.labels(**self.__labels).set(info.log_used)
            if self.__config.audit_key_id:
                self.retrieve_logs(hsm)
            if self.__config.application_key_id:
                self.encryption_test(hsm)
        except yubihsm.exceptions.YubiHsmConnectionError as e:
            logging.error('Failed to connect to %s: %s', self.__config.url, e)
            self.__metrics.test_errors.labels(**(self.__labels | {'error': 'connection'})).inc()


class ExitHandler:

    def __init__(self):
        self.__stop = False
        signal.signal(signal.SIGINT, self.exit)
        signal.signal(signal.SIGTERM, self.exit)

    @property
    def stop(self):
        return self.__stop

    def exit(self, *args):
        logging.info("Stopping ...")
        self.__stop = True


def main():
    logging.basicConfig(encoding='utf-8', level=logging.INFO)
    logging.info('YubiHSM Exporter starts')
    config_path = os.getenv('YUBIHSM_EXPORTER_CONFIG',
                            '/etc/yubihsm-export/config.json')
    logging.info('Load configuration from %s', config_path)
    config = load_configuration(config_path)
    prometheus_client.start_http_server(config.metrics_port)
    test_secret = TestSecret()
    metrics = Metrics()
    probes = [YubiHSMProbe(c, test_secret, metrics) for c in config.connectors]
    exit_handler = ExitHandler()
    while not exit_handler.stop:
        for probe in probes:
            probe.probe()
        logging.info("Sleep 5 seconds before probing next YubiHSM")
        time.sleep(SLEEP_TIME_BETWEEN_PROBES)


if __name__ == "__main__":
    main()

