#!/usr/bin/python3

import yubihsm
import logging
import os
import json
import prometheus_client
import time

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

    def __init__(self, url, application_key_id, application_key_pin_path,
                 audit_key_id, audit_key_pin_path, name):
        self.__url = url
        self.__application_key_id = application_key_id
        self.__application_key_pin_path = application_key_pin_path
        self.__audit_key_id = audit_key_id
        self.__audit_key_pin_path = audit_key_pin_path
        self.__name = name

    @staticmethod
    def load_config(data):
        expect_field(data, 'connectors', 'url', str),
        if 'application_key_id' in data:
             expect_field(data, 'connectors', 'application_key_id', int)
             expect_field(data, 'connectors', 'application_key_pin_path', str)
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


class YubiHSMProbe:

    def __init__(self, config):
        self.__config = config
        self.__labels = dict(url=self.__config.url,
                             name=self.__config.name) 
        self.__info = prometheus_client.Info(
                'yubihsm_device', 'Information about YubiHSM2 device',
                self.__labels.keys())
        self.__log_size = prometheus_client.Gauge(
                'yubihsm_log_size', 'Number of log entry in YubiHSM',
                self.__labels.keys())
        self.__used_log_entries = prometheus_client.Gauge(
                'yubihsm_used_log_entries', 'Number of used log entries in YubiHSM',
                self.__labels.keys())
        self.__previous_log_entry = None

    def retrieve_logs(self, hsm):
        try:
            logging.info(load_pin(self.__config.audit_key_pin_path))
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
            finally:
                session.close()
        except yubihsm.exceptions.YubiHsmError as e:
            logging.error('Failed to retrieve logs from %s: %s, %s', 
                          self.__config.url, type(e).__name__, str(e))

    def probe(self):
        logging.info('Connect to YubiHSM connector %s', self.__config.url)
        hsm = yubihsm.YubiHsm.connect(self.__config.url)
        try:
            info = hsm.get_device_info()
            self.__info.labels(**self.__labels).info(
                    {'version': version_to_string(info.version),
                     'serial': str(info.serial)})
            self.__log_size.labels(**self.__labels).set(info.log_size)
            self.__used_log_entries.labels(**self.__labels).set(info.log_used)
            if self.__config.audit_key_id:
                self.retrieve_logs(hsm)
        except yubihsm.exceptions.YubiHsmConnectionError as e:
            logging.error('Failed to connect to %s: %s', self.__config.url, e)


def main():
    logging.basicConfig(encoding='utf-8', level=logging.INFO)
    logging.info('YubiHSM Exporter starts')
    config_path = os.getenv('YUBIHSM_EXPORTER_CONFIG',
                            '/etc/yubihsm-export/config.json')
    logging.info('Load configuration from %s', config_path)
    config = load_configuration(config_path)
    prometheus_client.start_http_server(config.metrics_port)
    probes = [YubiHSMProbe(c) for c in config.connectors]
    while True:
        for probe in probes:
            probe.probe()
        time.sleep(1) # FIXME


if __name__ == "__main__":
    main()

