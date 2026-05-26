#! /bin/sh

PACKAGE_VERSION="$1"

cd dnscrypt-proxy || exit 1

go clean
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v3 go build -mod vendor -ldflags="-s -w"
mkdir linux-x86_64
ln dnscrypt-proxy linux-x86_64/
cp ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt linux-x86_64/
tar czpvf dnscrypt-proxy-linux_x86_64-${PACKAGE_VERSION:-dev}.tar.gz linux-x86_64

ls -l dnscrypt-proxy-*.tar.gz
