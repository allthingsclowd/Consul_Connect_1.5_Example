consul {
  address = "127.0.0.1:8321"
  ssl       = true
  ca_file   = "/etc/nomad.d/pki/tls/certs/consul/consul-ca.pem"
  cert_file = "/etc/nomad.d/pki/tls/certs/consul/server.pem"
  key_file  = "/etc/nomad.d/pki/tls/private/consul/server-key.pem"
  token = "19dda8de-d428-9b18-6ecd-82a50d7da042"
  }
