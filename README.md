# YubiHSM Prometheus Exporter

Exports the state of YubiHSM2 devices in a Prometheus compatible format.

# Stuff

Manually install into namespace *yubihsm-exporter-test* on lab.

```
lukas@lukas-t14s:~$ kubectl create ns yubihsm-exporter-test
    [...]
# Login into lab Vault
lukas@lukas-t14s:~$ vault kv put app/yubihsm-exporter-test/keys audit="$(pass show vault/lab/yubi-hsm-audit-pin)" application="$(pass show vault/lab/yubi-hsm-pin)"
    Key              Value
    ---              -----
    created_time     2021-10-06T09:30:26.018423837Z
    deletion_time    n/a
    destroyed        false
    version          3
#
# Adapt chart/yubihsm-prometheus-exporter/examples/values.lab to refer the vault version
# or let the version reference away.
#
lukas@lukas-t14s:~/Development/yubihsm-prometheus-exporter/chart/yubihsm-prometheus-exporter$ \
    helm -n yubihsm-exporter-test upgrade --install test . -f examples/values.lab 
```
