import threading
import os
import tempfile
import json
import sys
import subprocess
import time
import datetime

import requests
import prometheus_client.parser


TEST_YUBIHSM_CONNECTOR = os.getenv('TEST_YUBIHSM_CONNECTOR',
        'http://172.17.0.1:9010') 
TEST_YUBIHSM_AUDIT_KEY_ID = os.getenv('TEST_YUBIHSM_AUDIT_KEY_ID', '6')
TEST_YUBIHSM_AUDIT_KEY_PIN = os.getenv('TEST_YUBIHSM_AUDIT_KEY_PIN', None)
TEST_YUBIHSM_APP_KEY_ID = os.getenv('TEST_YUBIHSM_APP_KEY_ID', '3')
TEST_YUBIHSM_APP_KEY_PIN = os.getenv('TEST_YUBIHSM_APP_KEY_PIN', None)
TEST_KEY_LABEL = os.getenv('TEST_KEY_LABEL', 'vault-hsm-key')
TEST_PORT = os.getenv('TEST_PORT', '8080')


def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)


def create_test_config(temp_dir):
    if not TEST_YUBIHSM_AUDIT_KEY_PIN:
        raise ValueError('Set environment variable TEST_YUBIHSM_AUDIT_KEY_PIN')
    if not TEST_YUBIHSM_APP_KEY_PIN:
        raise ValueError('Set environment variable TEST_YUBIHSM_APP_KEY_PIN')
    path = temp_dir.name
    audit_pin_path = os.path.join(path, 'audit')
    app_pin_path = os.path.join(path, 'application')
    write_file(audit_pin_path, TEST_YUBIHSM_AUDIT_KEY_PIN)
    write_file(app_pin_path, TEST_YUBIHSM_APP_KEY_PIN)
    yubihsm = dict(name='1. HSM', url=TEST_YUBIHSM_CONNECTOR,
            audit_key_id=int(TEST_YUBIHSM_AUDIT_KEY_ID), 
            audit_key_pin_path=audit_pin_path,
            application_key_id=int(TEST_YUBIHSM_APP_KEY_ID),
            application_key_pin_path=app_pin_path,
            encryption_key_label=TEST_KEY_LABEL)
    misconfigured_hsm = dict(yubihsm)
    misconfigured_hsm['name'] = 'misconfigured_hsm'
    misconfigured_hsm['application_key_pin_path'] = audit_pin_path
    misconfigured_hsm['audit_key_pin_path'] = app_pin_path
    non_existing_hsm = dict(name='3. HSM', url='http://somewhere-some.time')
    config = dict(metrics_port=int(TEST_PORT),
                  connectors=[yubihsm, misconfigured_hsm, non_existing_hsm])
    config_path = os.path.join(path, 'cfg')
    with open(config_path, 'w') as cfg_file:
        json.dump(config, cfg_file)
    return config_path


def start_exporter_instance(config_path):
    process = subprocess.Popen([sys.executable, 'main.py'], 
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'YUBIHSM_EXPORTER_CONFIG': config_path})
    return process


def retrieve_metrics(url):
    try:
        r = requests.get(url)
        return prometheus_client.parser.text_string_to_metric_families(r.text)
    except requests.exceptions.ConnectionError:
        return None


def scrape(url, duration, sleep_duration=1):
    METRICS_OF_INTEREST = ('yubihsm_test_errors_total', 'yubihsm_device_info',
            'yubihsm_log_size', 'yubihsm_used_log_entries', 
            'yubihsm_test_connections_total')
    samples = list()
    start_time = datetime.datetime.now()
    while (datetime.datetime.now() - start_time).total_seconds() < duration:
        metrics = retrieve_metrics(url)
        if metrics:
            for family in metrics:
                for sample in family.samples:
                    if sample.name in METRICS_OF_INTEREST:
                        samples.append(sample)
        time.sleep(sleep_duration)
    return samples


def test_metric_retrieval():
    temp_dir = tempfile.TemporaryDirectory()
    config_path = create_test_config(temp_dir)
    process = start_exporter_instance(config_path)
    metrics_url = 'http://localhost:%s' % TEST_PORT
    samples = scrape(metrics_url, 30)
    process.send_signal(15)
    hsms = set((x.labels['name'], x.labels['url']) for x in samples)
    assert ('1. HSM', TEST_YUBIHSM_CONNECTOR) in hsms
    assert ('misconfigured_hsm', 'http://172.17.0.1:9010') in hsms
    assert ('3. HSM', 'http://somewhere-some.time') in hsms
    device_info = next(x for x in samples 
            if x.labels['name']=='1. HSM' and x.name=='yubihsm_device_info')
    assert 'version' in device_info.labels
    assert 'serial' in device_info.labels
    assert any(x for x in samples if x.labels['name']=='1. HSM' 
            and x.name=='yubihsm_log_size')
    assert any(x for x in samples if x.labels['name']=='1. HSM'
            and x.name=='yubihsm_used_log_entries')
    assert any(x for x in samples
            if x.labels['name']=='misconfigured_hsm'
            and x.name=='yubihsm_test_errors_total' 
            and x.labels['error']=='get_logs')
    assert any(x for x in samples
            if x.labels['name']=='misconfigured_hsm'
            and x.name=='yubihsm_test_errors_total' 
            and x.labels['error']=='crypto_test')
    connection_errors = max(x.value for x in samples
            if x.labels['name']=='3. HSM'
            and x.name=='yubihsm_test_errors_total' 
            and x.labels['error']=='connection')
    tries = max(x.value for x in samples
            if x.labels['name']=='3. HSM'
            and x.name=='yubihsm_test_connections_total')
    assert connection_errors == tries
    assert tries > 1
    assert not any(x for x in samples
            if x.labels['name']=='1. HSM'
            and x.name=='yubihsm_test_errors_total')
    min_tries = min(x.value for x in samples
            if x.labels['name']=='1. HSM'
            and x.name=='yubihsm_test_connections_total')
    max_tries = max(x.value for x in samples
            if x.labels['name']=='1. HSM'
            and x.name=='yubihsm_test_connections_total')
    assert max_tries - min_tries > 1
    print(process.communicate())

