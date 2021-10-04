#!/usr/bin/python3

import yubihsm
import logging
import os
import json


def expect_field(data, context, name, t):
    if name not in data or not isinstance(data[name], t):
        logging.error('Expected field %s of type %v in %s', name, t, context)
        exit(1)
    else:
        return data[name]


class YubiHSMConfiguration:

    @property
    def connector_url(self):
        return self.__connector_url

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

    @staticmethod
    def load_config(data):
        pass


class Configuration:
   
    def __init__(self, connectors):
        self.__connectors = connectors

    @property
    def connectors(self):
        return self.__connectors

    @staticmethod
    def load_config(data):
        connectors = expect_field(data, '""', 'connectors', list)
        return Configuration(
                connectors=[YubiHSMConfiguration.load_config(c)
                            for c in connectors])


def load_configuration(path):
    with open(path) as config_file:
        data = json.load(config_file)
        return Configuration.load_config(data)


def main():
    logging.basicConfig(encoding='utf-8', level=logging.INFO)
    logging.info('YubiHSM Exporter starts')
    config_path = os.getenv('YUBIHSM_EXPORTER_CONFIG',
                            '/etc/yubihsm-export/config.json')
    logging.info('Load configuration from %s' % config_path)
    config = load_configuration(config_path)


if __name__ == "__main__":
    main()

