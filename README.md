# `infrapki`

Exploration of the [Python Cryptography](https://github.com/pyca/cryptography) package.

## Usage

### Install

Git clone and Python setup:

```
git clone github.com/oko/infrapki
pipenv install
pipenv run -- python3 setup.py install
```

### Root CAs

Create a demonstrator root CA:

```
# creates a root CA in `path/to/dir`
pipenv run -- infrapki ca new path/to/dir example/root.infrapki.conf.toml
```

Root CAs are generated without a basic constraint path length. The path length used during signing of an intermediate is determined by the config file's `ca.ca_path_length` option.

### Intermediate CAs

See `scripts/testint.sh` for a demonstration of intermediate CAs.

### Server Certs

Currently the `infrapki ca sign` command selects the signing mode based whether the CA in use is a root or intermediate:

* If it's a root CA, sign the CSR as if it's an intermediate CA
* If it's an intermediate CA, sign the CSR as if it's a server certificate

### External CSRs

InfraPKI can sign external CSRs (i.e. those created by Vault) with:

```
infrapki ca sign <ca-dir> <csr-path> <cert-output-path>
```

## Things to Implement

* CA certificate databases
* CA CRL generation
