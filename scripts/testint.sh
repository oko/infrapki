#!/bin/bash
set -eux
rm -rf testint testroot
# install
pipenv run python3 setup.py install
# create root CA
pipenv run -- infrapki --debug ca new testroot example/root.infrapki.ca.toml
# create intermediate CA CSR
pipenv run -- infrapki --debug ca new testint example/int.infrapki.ca.toml
# dump CSR
openssl req -in testint/public/ca.csr.pem -noout -text
# sign CSR with root CA
pipenv run -- infrapki --debug ca sign testroot testint/public/ca.csr.pem testint/public/ca.cert.pem

# dump cert and run verification of intermediate
openssl x509 -in testint/public/ca.cert.pem -noout -text
openssl verify -CAfile testroot/public/ca.cert.pem testint/public/ca.cert.pem

# create server certificate from intermediate
sdir="$(mktemp -d)"
echo "------------- generating server cert"
openssl req -nodes -newkey rsa:2048 -keyout "$sdir/key" -out "$sdir/csr" -subj "/C=US/ST=California/L=San Francisco/O=InfraPKI/CN=infrapki.example.com"
pipenv run -- infrapki --debug ca sign testint "$sdir/csr" "$sdir/cert"
openssl x509 -in "$sdir/cert" -noout -text

# verify leaf certificate against root with chain
cat "$sdir/cert" testint/public/ca.cert.pem > "$sdir/chain"
openssl verify -CAfile testroot/public/ca.cert.pem -untrusted "$sdir/chain" "$sdir/cert"

echo "------------- generating client cert"
sdir="$(mktemp -d)"
openssl req -nodes -newkey rsa:2048 -keyout "$sdir/key" -out "$sdir/csr" -subj "/C=US/ST=California/L=San Francisco/O=InfraPKI/CN=oko@oko.io"
pipenv run -- infrapki --debug ca sign testint "$sdir/csr" "$sdir/cert" --client
openssl x509 -in "$sdir/cert" -noout -text

# verify leaf certificate against root with chain
cat "$sdir/cert" testint/public/ca.cert.pem > "$sdir/chain"
openssl verify -CAfile testroot/public/ca.cert.pem -untrusted "$sdir/chain" "$sdir/cert"
