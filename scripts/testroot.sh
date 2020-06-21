#!/bin/bash
rm -rf testroot
pipenv run python3 setup.py install
pipenv run -- infrapki --debug ca new testroot example/root.infrapki.ca.toml --no-passphrase
openssl x509 -in testroot/public/ca.cert.pem -noout -text
