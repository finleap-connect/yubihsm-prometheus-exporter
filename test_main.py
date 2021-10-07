from unittest.mock import patch, mock_open

import main

import pytest
import prometheus_client

def test_expect_field():
    assert main.expect_field(dict(foo='bar'), '', 'foo', str) == 'bar'
    with patch('main.exit') as exit_mock:
        main.expect_field(dict(foo='bar'), '', 'foo2', str)
        assert exit_mock.called
        main.expect_field(dict(foo='bar'), '', 'foo', int)
        assert exit_mock.called
        

def test_parsing_minimal_configuration():
    config = main.Configuration.load_config(dict(
        connectors=[
            dict(url='http://6.6.6.6:777'),
            dict(url='https://no.name:port')]))
    assert config.metrics_port == 8080
    assert config.connectors[0].url == 'http://6.6.6.6:777'
    assert config.connectors[0].application_key_id is None
    assert config.connectors[0].audit_key_id is None
    assert config.connectors[0].name == ''
    assert config.connectors[1].url == 'https://no.name:port'
    assert len(config.connectors) == 2


def test_loading_full_configuration():
    config = main.Configuration.load_config(dict(
        metrics_port=7777,
        connectors=[
            dict(
                application_key_id=7,
                application_key_pin_path='foo/bar/app',
                encryption_key_label='test',
                audit_key_id=8,
                audit_key_pin_path='foo/bar/audit',
                name='frog',
                url='http://6.6.6.6:777'),
            dict(
                url='https://no.name:port')]))
    assert config.metrics_port == 7777
    assert config.connectors[0].url == 'http://6.6.6.6:777'
    assert config.connectors[0].application_key_id == 7
    assert config.connectors[0].application_key_pin_path == 'foo/bar/app'
    assert config.connectors[0].encryption_key_label == 'test'
    assert config.connectors[0].audit_key_id == 8
    assert config.connectors[0].audit_key_pin_path == 'foo/bar/audit'
    assert config.connectors[0].name == 'frog'   
    assert config.connectors[1].url == 'https://no.name:port'
    assert len(config.connectors) == 2


invalid_configs=[
    dict(),
    dict(connectors='blubb'),
    dict(connectors=[dict()]),
    dict(connectors=[dict(
        url='sds', audit_key_id='7', audit_key_pin_path='foo/bar')]),
    dict(connectors=[dict(url='sds', audit_key_id=7)]),
    dict(connectors=[dict(url='sds', application_key_id=7)]),
]


@pytest.mark.parametrize('config', invalid_configs)
def test_loading_wrong_configurations(config):
    with pytest.raises(SystemExit):    
        main.Configuration.load_config(config)


def test_load_configuration():
    with patch('main.open') as open_mock, patch('json.load') as json_load:
        json_load.return_value = dict(connectors=[])
        config = main.load_configuration('foo/bar')
        assert config.metrics_port == 8080
        assert config.connectors == []
        open_mock.assert_called_once_with('foo/bar')
        assert json_load.called


def test_version_to_string():
    assert main.version_to_string((5, 6, 7)) == '5.6.7'


def test_load_pin():
    with patch('builtins.open', mock_open(read_data='prince')) as open_mock:
        assert main.load_pin('frog') == 'prince'
        open_mock.assert_called_with('frog')
    with pytest.raises(SystemExit):
        main.load_pin('does/not/exist')


def test_test_secret():
    test_secret = main.TestSecret('🤴')
    assert test_secret.secret == '🤴'
    assert test_secret.get() == ('🤴', False)
    curse = lambda x: '🐸'.encode('utf8') if x == '🤴'.encode('utf8') else None
    kiss = lambda x: '🤴'.encode('utf8') if x == '🐸'.encode('utf8') else '💓'
    test_secret.process(encrypt=curse, decrypt=kiss)
    assert test_secret.get() == ('f09f90b8', True)
    test_secret.process(encrypt=curse, decrypt=kiss)
    assert test_secret.secret == '🤴'
    assert test_secret.get() == ('🤴', False)


def test_default_secret():
    assert main.TestSecret.DEFAULT_SECRET == main.TestSecret().secret


def test_metrics_helper():
    metrics = main.Metrics()
    assert isinstance(metrics.info.labels(url='mu', name='ma'),
            prometheus_client.Info)
    assert isinstance(metrics.log_size.labels(url='mu', name='ma'),
            prometheus_client.Gauge)
    assert isinstance(metrics.used_log_entries.labels(url='mu', name='ma'),
            prometheus_client.Gauge)
    assert isinstance(metrics.test_connections.labels(url='mu', name='ma'),
            prometheus_client.Counter)
    assert isinstance(
            metrics.test_errors.labels(url='mu', name='ma', error='mi'),
            prometheus_client.Counter)


