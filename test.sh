#!/bin/bash

pin_directory=$(mktemp -d)
cleanup() {
	echo "Cleanup"
	rm -frv "$pin_directory"
}
trap cleanup EXIT

mkdir -p "$pin_directory"
echo "Get secrets for lab from pass"
echo "#############################"
echo ""
pass show vault/lab/yubi-hsm-audit-pin > "$pin_directory/audit"
echo "wrong-pin" > "$pin_directory/application"
#pass show vault/lab/yubi-hsm-pin > "$pin_directory/application"
docker build -t test .
docker run -v $(pwd)/test-config.json:/etc/yubihsm-export/config.json \
	-v "$pin_directory/audit":/secrets/audit-key-pin \
	-v "$pin_directory/application":/secrets/application-key-pin \
	-p 8080:8080 -it test

