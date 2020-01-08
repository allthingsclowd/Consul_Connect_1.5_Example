#!/usr/bin/env bash

set -x

setup_environment () {

    # Configure consul environment variables for use with certificates 
    export CONSUL_HTTP_ADDR=https://127.0.0.1:8321
    export CONSUL_CACERT=/usr/local/bootstrap/certificate-config/consul-ca.pem
    export CONSUL_CLIENT_CERT=/usr/local/bootstrap/certificate-config/cli.pem
    export CONSUL_CLIENT_KEY=/usr/local/bootstrap/certificate-config/cli-key.pem

    export VAULT_TOKEN=reallystrongpassword
    export VAULT_ADDR=https://192.168.4.11:8322
    export VAULT_CLIENT_KEY=/usr/local/bootstrap/certificate-config/hashistack-client-key.pem
    export VAULT_CLIENT_CERT=/usr/local/bootstrap/certificate-config/hashistack-client.pem
    export VAULT_CACERT=/usr/local/bootstrap/certificate-config/hashistack-ca.pem
  
    AGENTTOKEN=`vault kv get -field "value" kv/development/consulagentacl`
    export CONSUL_HTTP_TOKEN=${AGENTTOKEN}
    export CONSUL_HTTP_SSL=true
    export CONSUL_GRPC_ADDR=127.0.0.1:8502

}

install_demo_app() {
  
  pushd /usr/local/bin
  sudo wget -q https://github.com/hashicorp/http-echo/releases/download/v0.2.3/http-echo_0.2.3_linux_amd64.zip
  sudo unzip http-echo_0.2.3_linux_amd64.zip
  chmod +x http-echo
  rm http-echo_0.2.3_linux_amd64.zip
  popd
  
}






install_demo_app
