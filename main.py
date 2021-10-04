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

    def __init__(self, url, application_key_id, application_key_pin_path,
                 audit_key_id, audit_key_pin_path):
        self.__url = url
        self.__application_key_id = application_key_id
        self.__application_key_pin_path = application_key_pin_path
        self.__audit_key_id = audit_key_id
        self.__audit_key_pin_path = audit_key_pin_path

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


class YubiHSMProbe:

    def __init__(self, config):
        self.__config = config
        self.__labels = dict(url=self.__config.url)
        self.__info = prometheus_client.Info('yubihsm_device', 
                                             'Information about YubiHSM2 device',
                                             self.__labels.keys())

    def probe(self):
        logging.info('Connect to YubiHSM connector %s', self.__config.url)
        hsm = yubihsm.YubiHsm.connect(self.__config.url)
        try:
            info = hsm.get_device_info()
            self.__info.labels(**self.__labels).info({'version': str(info.version)})
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

