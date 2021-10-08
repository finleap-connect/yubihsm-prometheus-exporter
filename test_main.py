from unittest.mock import patch, mock_open, MagicMock, ANY, PropertyMock
from collections import namedtuple

import pytest
import prometheus_client
import yubihsm

import main


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


DeviceInfo = namedtuple(
    'DeviceInfo', ['version', 'serial', 'log_size', 'log_used']
)


LogData = namedtuple('LogData', ['entries'])


def prepare_probe_under_test(metrics_mock, with_audit=True, with_encryption=True):
    test_secret = main.TestSecret('mySecret')
    connector = main.YubiHSMConfiguration(
            url='http://first-node.de',
            audit_key_id=7 if with_audit else None,
            audit_key_pin_path='foo/bar/audit',
            application_key_id=8 if with_encryption else None, 
            application_key_pin_path='application/',
            encryption_key_label='foo')
    probe = main.YubiHSMProbe(connector, test_secret, metrics_mock)
    return probe, test_secret, connector


@patch('main.Metrics')
@patch('yubihsm.core.YubiHsm')
def test_yubihsm_full_successful_probe(yubihsm_mock, metrics_mock):
    probe, test_secret, _ = prepare_probe_under_test(metrics_mock)
    yubihsm_mock.get_device_info = MagicMock(return_value=DeviceInfo(
        version=(3, 4, 5), serial='6789', log_size=63, log_used=7))
    public_key = MagicMock()
    public_key.encrypt = MagicMock(return_value=b'encrypted')
    key_mock = MagicMock(spec=yubihsm.objects.AsymmetricKey)
    key_mock.get_public_key = MagicMock(return_value=public_key)
    key_mock.decrypt_pkcs1v1_5 = MagicMock(
            return_value=main.TestSecret.DEFAULT_SECRET.encode('utf8'))
    session_mock = MagicMock(spec=yubihsm.core.AuthSession)
    session_mock.list_objects = MagicMock(return_value=[key_mock])
    log_entries_mock = [MagicMock() for _ in range(2)]
    session_mock.get_log_entries = MagicMock(return_value=LogData(
        entries=log_entries_mock))
    yubihsm_mock.create_session_derived = MagicMock(return_value=session_mock)
    with patch('yubihsm.YubiHsm.connect', return_value=yubihsm_mock) as (
            connect_mock), patch('main.load_pin') as load_pin_mock:
        probe.probe()
        connect_mock.assert_called_once_with('http://first-node.de')
        assert yubihsm_mock.get_device_info.called
        # TODO: check actual values passed to the metric collectors
        expected_labels=dict(url='http://first-node.de', name='')
        metrics_mock.info.labels.assert_called_with(**expected_labels)
        metrics_mock.log_size.labels.assert_called_with(**expected_labels)
        metrics_mock.used_log_entries.labels.assert_called_with(
                **expected_labels)
        # Check log retrieval
        load_pin_mock.assert_any_call('foo/bar/audit')
        yubihsm_mock.create_session_derived.assert_any_call(7, ANY)
        assert session_mock.get_log_entries.called
        session_mock.set_log_index.assert_called_with(log_entries_mock[-1].number)
        # Check encryption test
        load_pin_mock.assert_any_call('application/')
        yubihsm_mock.create_session_derived.assert_any_call(8, ANY)
        session_mock.list_objects.assert_called_once_with(label='foo')
        assert key_mock.get_public_key.called
        public_key.encrypt.assert_called_once_with(b'mySecret', ANY)
        assert test_secret.get() == (b'encrypted'.hex(), True)
        assert not key_mock.decrypt_pkcs1v1_5.called
        key_mock.reset_mock()
        probe.probe()
        assert not key_mock.get_public_key.called
        key_mock.decrypt_pkcs1v1_5.assert_called_with(b'encrypted')
        assert test_secret.get() == (main.TestSecret.DEFAULT_SECRET, False)
        


@patch('main.Metrics')
@patch('yubihsm.core.YubiHsm')
def test_probe_connection_error(yubihsm_mock, metrics_mock):
    probe, test_secret, _ = prepare_probe_under_test(metrics_mock)
    yubihsm_mock.get_device_info.side_effect = yubihsm.exceptions.YubiHsmConnectionError()
    with patch('yubihsm.YubiHsm.connect', return_value=yubihsm_mock):
         probe.probe()
         metrics_mock.test_errors.labels.assert_called_with(
                 url='http://first-node.de', name='', error='connection')


@patch('main.load_pin')
@patch('main.Metrics')
@patch('yubihsm.core.YubiHsm')
def test_probe_log_retrieval_error(yubihsm_mock, metrics_mock, load_pin):
    probe, test_secret, _ = prepare_probe_under_test(metrics_mock, with_encryption=False)
    yubihsm_mock.get_device_info = MagicMock(return_value=DeviceInfo(
        version=(3, 4, 5), serial='6789', log_size=63, log_used=7))
    yubihsm_mock.create_session_derived.side_effect = yubihsm.exceptions.YubiHsmConnectionError()
    with patch('yubihsm.YubiHsm.connect', return_value=yubihsm_mock):
         probe.probe()
         assert load_pin.called
         metrics_mock.test_errors.labels.assert_called_with(
                 url='http://first-node.de', name='', error='get_logs')


@patch('main.load_pin')
@patch('main.Metrics')
@patch('yubihsm.core.YubiHsm')
def test_probe_failed_decryption(yubihsm_mock, metrics_mock, load_pin):
    probe, test_secret, _ = prepare_probe_under_test(metrics_mock, with_audit=False)
    yubihsm_mock.get_device_info = MagicMock(return_value=DeviceInfo(
        version=(3, 4, 5), serial='6789', log_size=63, log_used=7))
    key_mock = MagicMock(spec=yubihsm.objects.AsymmetricKey)
    key_mock.decrypt_pkcs1v1_5 = MagicMock(
            return_value='something'.encode('utf8'))
    session_mock = MagicMock(spec=yubihsm.core.AuthSession)
    session_mock.list_objects = MagicMock(return_value=[key_mock])
    yubihsm_mock.create_session_derived = MagicMock(return_value=session_mock)
    with patch('yubihsm.YubiHsm.connect', return_value=yubihsm_mock):
         test_secret.process(encrypt=lambda x: x, decrypt=lambda x: x)
         probe.probe()
         assert load_pin.called
         key_mock.decrypt_pkcs1v1_5.assert_called_with(b'mySecret')
         metrics_mock.test_errors.labels.assert_called_with(
                 url='http://first-node.de', name='', error='crypto_test')


@patch('main.load_pin')
@patch('main.Metrics')
@patch('yubihsm.core.YubiHsm')
def test_probe_failed_over_missing_key(yubihsm_mock, metrics_mock, load_pin):
    probe, test_secret, _ = prepare_probe_under_test(metrics_mock, with_audit=False)
    yubihsm_mock.get_device_info = MagicMock(return_value=DeviceInfo(
        version=(3, 4, 5), serial='6789', log_size=63, log_used=7))
    session_mock = MagicMock(spec=yubihsm.core.AuthSession)
    session_mock.list_objects = MagicMock(return_value=[])
    yubihsm_mock.create_session_derived = MagicMock(return_value=session_mock)
    with patch('yubihsm.YubiHsm.connect', return_value=yubihsm_mock):
         test_secret.process(encrypt=lambda x: x, decrypt=lambda x: x)
         probe.probe()
         assert load_pin.called
         session_mock.list_objects.assert_called_with(label='foo')
         metrics_mock.test_errors.labels.assert_called_with(
                 url='http://first-node.de', name='', error='crypto_test')

@patch('main.YubiHSMProbe')
@patch('main.Metrics')
@patch('prometheus_client.start_http_server')
@patch('main.load_configuration')
def test_main(load_config_mock, start_server_mock, metrics_mock, probe_mock):
    hsm_config = main.YubiHSMConfiguration(url='www.somewhere.de')
    load_config_mock.return_value = main.Configuration(
            metrics_port=8787, connectors=[hsm_config])
    main.SLEEP_TIME_BETWEEN_PROBES = 0
    prober_mock = probe_mock()
    probe_mock.return_value = prober_mock
    with patch('main.ExitHandler.stop', new_callable=PropertyMock) as stop_mock:
        stop_mock.side_effect = [False, True]
        handler = main.ExitHandler()
        main.main()
        assert prober_mock.probe.called
        probe_mock.assert_called_with(hsm_config, ANY, ANY)
        start_server_mock.assert_called_with(8787)
        load_config_mock.assert_called_with('/etc/yubihsm-export/config.json')


def test_exit_handler():
    handler = main.ExitHandler()
    handler.exit()
    assert handler.stop

