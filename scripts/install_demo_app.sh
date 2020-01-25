#!/usr/bin/env bash

set -x

create_service () {
  if [ ! -f /etc/systemd/system/${1}.service ]; then
    
    create_service_user ${1}
    
    sudo tee /etc/systemd/system/${1}.service <<EOF
### BEGIN INIT INFO
# Provides:          ${1}
# Required-Start:    $local_fs $remote_fs
# Required-Stop:     $local_fs $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: ${1} agent
# Description:       ${2}
### END INIT INFO

[Unit]
Description=${2}
Requires=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=${4}
User=${1}
Group=${1}
PIDFile=/var/run/${1}/${1}.pid
PermissionsStartOnly=true
ExecStartPre=/bin/mkdir -p /var/run/${1}
ExecStartPre=/bin/chown -R ${1}:${1} /var/run/${1}
ExecStart=${3}
ExecReload=/bin/kill -HUP ${MAINPID}
KillMode=process
KillSignal=SIGTERM
Restart=on-failure
RestartSec=2s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

  fi

}

create_service_user () {
  
  if ! grep ${1} /etc/passwd >/dev/null 2>&1; then
    
    echo "Creating ${1} user to run the ${1} service"
    sudo groupadd -f -r ${1}
    sudo useradd -g ${1} --system --home-dir /etc/${1}.d --create-home --shell /bin/false ${1}
    sudo mkdir --parents /opt/${1} /usr/local/${1} /etc/${1}.d
    sudo chown -R ${1}:${1} /opt/${1} /usr/local/${1} /etc/${1}.d

  fi

}

create_demo_app_service () {
    
    create_service demoapp "HashiCorp Consul Connect Demo Service" "/usr/local/bin/http-echo -listen=\"127.0.0.1:9090\" -text=\"Hello from ${HOSTNAME} application server!\"" simple
    sudo systemctl enable demoapp
    sudo systemctl start demoapp

}

setup_environment () {

  # Configure consul environment variables for use with certificates 
  export CONSUL_HTTP_ADDR=https://127.0.0.1:8321
  export CONSUL_CACERT=/usr/local/bootstrap/certificate-config/consul-ca.pem
  export CONSUL_CLIENT_CERT=/usr/local/bootstrap/certificate-config/cli.pem
  export CONSUL_CLIENT_KEY=/usr/local/bootstrap/certificate-config/cli-key.pem

  export VAULT_TOKEN=reallystrongpassword
  export VAULT_ADDR=https://192.168.4.11:8322
  export VAULT_CLIENT_KEY=/usr/local/bootstrap/certificate-config/client-key.pem
  export VAULT_CLIENT_CERT=/usr/local/bootstrap/certificate-config/client.pem
  export VAULT_CACERT=/usr/local/bootstrap/certificate-config/consul-ca.pem

  AGENTTOKEN=`vault kv get -field "value" kv/development/consulagentacl`
  export CONSUL_HTTP_TOKEN=${AGENTTOKEN}
  export CONSUL_HTTP_SSL=true
  export CONSUL_GRPC_ADDR=https://127.0.0.1:8502

  SERVICETOKEN=`vault kv get -field "value" kv/development/SERVICETOKEN`
  export SERVICETOKEN
  
}

install_demo_app() {
  
  pushd /usr/local/bin
  sudo wget -q https://github.com/hashicorp/http-echo/releases/download/v0.2.3/http-echo_0.2.3_linux_amd64.zip
  sudo unzip http-echo_0.2.3_linux_amd64.zip
  chmod +x http-echo
  rm http-echo_0.2.3_linux_amd64.zip
  popd
  
}

register_demo_app_service () {

  # configure http-echo service definition
  tee httpecho_service.json <<EOF
  {
    "ID": "httpecho",
    "Name": "httpecho",
    "Tags": [
      "primary",
      "v1"
    ],
    "Address": "127.0.0.1",
    "Port": 9090,
    "checks": [
        {
          "name": "Demo Consul Connect Service",
          "http": "http://127.0.0.1:9090",
          "tls_skip_verify": true,
          "method": "GET",
          "interval": "10s",
          "timeout": "5s"
        }
    ],
    "connect": { "sidecar_service": {} },
    "Meta": {
      "httpecho_version": "1.0"
    },
    "EnableTagOverride": false
  }
EOF

  # Register the service in consul via the local Consul agent api
  sudo curl \
      -s -w "\n\n\tRESPONSE CODE :\t%{http_code}\n" \
      --request PUT \
      --cacert "/usr/local/bootstrap/certificate-config/consul-ca.pem" \
      --key "/usr/local/bootstrap/certificate-config/client-key.pem" \
      --cert "/usr/local/bootstrap/certificate-config/client.pem" \
      --header "X-Consul-Token: ${AGENTTOKEN}" \
      --data @httpecho_service.json \
      ${CONSUL_HTTP_ADDR}/v1/agent/service/register

}

dump_envoy_config () {
  /usr/local/bin/consul connect envoy \
                            -http-addr=https://127.0.0.1:8321 \
                            -ca-file=/usr/local/bootstrap/certificate-config/consul-ca.pem \
                            -client-cert=/usr/local/bootstrap/certificate-config/cli.pem \
                            -client-key=/usr/local/bootstrap/certificate-config/cli-key.pem \
                            -token=${SERVICETOKEN} \
                            -sidecar-for httpecho \
                            -bootstrap
}

setup_environment
register_demo_app_service
install_demo_app
create_demo_app_service
dump_envoy_config

