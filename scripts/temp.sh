  {
  "datacenter": "allthingscloud1",
  "data_dir": "/usr/local/consul",
  "encrypt" : "mUIJq6TITeenfVa2yMSi6yLwxrz2AYcC0dXissYpOxE=",
  "log_level": "INFO",
  "server": true,
  "node_name": "leader010",
  "addresses": {
      "https": "0.0.0.0"
  },
  "ports": {
      "https": 8321,
      "http": -1,
      "grpc": 8502
  },
  "verify_incoming": true,
  "verify_outgoing": true,
  "key_file": "/etc/consul.d/pki/tls/private/consul/server-key.pem",
  "cert_file": "/etc/consul.d/pki/tls/certs/consul/server.pem",
  "ca_file": "/etc/consul.d/pki/tls/certs/consul/consul-ca.pem"
  }


datacenter = "allthingscloud1"
data_dir = "/usr/local/consul"
encrypt = "mUIJq6TITeenfVa2yMSi6yLwxrz2AYcC0dXissYpOxE="
log_level = "INFO"
server = true
node_name = "leader010"
addresses {
    https = "0.0.0.0"
}
ports {
    https = 8321
    http = -1
    grpc = 8502
}
connect {
    enabled = true
}
verify_incoming = true
verify_outgoing = true
key_file = "/etc/consul.d/pki/tls/private/consul/server-key.pem"
cert_file = "/etc/consul.d/pki/tls/certs/consul/server.pem"
ca_file = "/etc/consul.d/pki/tls/certs/consul/consul-ca.pem"


  sudo tee /etc/consul.d/consul_acl_1.4_setup.json <<EOF
  {
  "acl" : {
    "enabled" : true,
    "default_policy" : "deny",
    "down_policy" : "extend-cache",
    "tokens" : {
      "agent" : "${AGENTTOKEN}"
    }
  }
}
EOF

  sudo tee /etc/consul.d/consul_acl_1.4_client_setup.hcl <<EOF
acl {
    enabled =  true
    default_policy = "deny"
    down_policy =  "extend-cache"
    tokens {
        agent = "${AGENTTOKEN}"
            }
}
EOF

  sudo tee /etc/consul.d/consul_acl_1.4_server_setup.hcl <<EOF 
primary_datacenter = "allthingscloud1"
acl {
    enabled = true
    default_policy = "deny"
    down_policy = "extend-cache"
    tokens {
        agent = "${AGENTTOKEN}"
            }
    }
EOF
