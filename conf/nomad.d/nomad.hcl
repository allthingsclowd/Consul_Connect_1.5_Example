consul {
  address = "127.0.0.1:8321"
  ssl       = true
  ca_file   = "/etc/nomad.d/pki/tls/certs/consul/consul-ca.pem"
  cert_file = "/etc/nomad.d/pki/tls/certs/consul/server.pem"
  key_file  = "/etc/nomad.d/pki/tls/private/consul/server-key.pem"
  token = "805bf5ea-5190-e30a-ee94-b83637c09d58"
  }
