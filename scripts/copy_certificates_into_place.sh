#!/usr/bin/env bash

set -x

# copy the example certificates into the correct location - PLEASE CHANGE THESE FOR A PRODUCTION DEPLOYMENT

# move vault certificates into place
sudo -u vault mkdir --parents /etc/vault.d/pki/tls/private/vault /etc/vault.d/pki/tls/certs/vault
sudo -u vault mkdir --parents /etc/vault.d/pki/tls/private/consul /etc/vault.d/pki/tls/certs/consul

# temp hack replace vault certs with consul certs
sudo -u vault cp -r /usr/local/bootstrap/certificate-config/server-key.pem /usr/local/bootstrap/certificate-config/hashistack-server-key.pem
sudo -u vault cp -r /usr/local/bootstrap/certificate-config/server.pem /usr/local/bootstrap/certificate-config/hashistack-server.pem
sudo -u vault cp -r /usr/local/bootstrap/certificate-config/consul-ca.pem /usr/local/bootstrap/certificate-config/consul-ca.pem

sudo -u vault cp -r /usr/local/bootstrap/certificate-config/hashistack-server-key.pem /etc/vault.d/pki/tls/private/vault/hashistack-server-key.pem
sudo -u vault cp -r /usr/local/bootstrap/certificate-config/hashistack-server.pem /etc/vault.d/pki/tls/certs/vault/hashistack-server.pem

sudo -u vault cp -r /usr/local/bootstrap/certificate-config/server-key.pem /etc/vault.d/pki/tls/private/consul/server-key.pem
sudo -u vault cp -r /usr/local/bootstrap/certificate-config/server.pem /etc/vault.d/pki/tls/certs/consul/server.pem
sudo -u vault cp -r /usr/local/bootstrap/certificate-config/consul-ca.pem /etc/vault.d/pki/tls/certs/consul/consul-ca.pem

# move consul certificates into place
sudo -u consul mkdir --parents /etc/consul.d/pki/tls/private/vault /etc/consul.d/pki/tls/certs/vault
sudo -u consul mkdir --parents /etc/consul.d/pki/tls/private/consul /etc/consul.d/pki/tls/certs/consul

sudo -u consul cp -r /usr/local/bootstrap/certificate-config/server-key.pem /etc/consul.d/pki/tls/private/consul/server-key.pem
sudo -u consul cp -r /usr/local/bootstrap/certificate-config/server.pem /etc/consul.d/pki/tls/certs/consul/server.pem
sudo -u consul cp -r /usr/local/bootstrap/certificate-config/consul-ca.pem /etc/consul.d/pki/tls/certs/consul/consul-ca.pem

# move nomad certificates into place
sudo -u nomad mkdir --parents /etc/nomad.d/pki/tls/private/nomad /etc/nomad.d/pki/tls/certs/nomad
sudo -u nomad mkdir --parents /etc/nomad.d/pki/tls/private/consul /etc/nomad.d/pki/tls/certs/consul

sudo -u nomad cp -r /usr/local/bootstrap/certificate-config/server-key.pem /etc/nomad.d/pki/tls/private/consul/server-key.pem
sudo -u nomad cp -r /usr/local/bootstrap/certificate-config/server.pem /etc/nomad.d/pki/tls/certs/consul/server.pem
sudo -u nomad cp -r /usr/local/bootstrap/certificate-config/consul-ca.pem /etc/nomad.d/pki/tls/certs/consul/consul-ca.pem
