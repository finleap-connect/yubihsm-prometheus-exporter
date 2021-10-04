#!/bin/bash

docker build -t test .
docker run -v $(pwd)/test-config.json:/etc/yubihsm-export/config.json -p 8080:8080 -it test

