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