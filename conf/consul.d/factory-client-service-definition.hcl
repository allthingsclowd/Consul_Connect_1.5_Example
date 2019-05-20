services {
  name = "client"
  port = 1234
  connect {
    sidecar_service {
      proxy {
        upstreams {
          destination_name = "http-echo"
          local_bind_port = 9091
        }
      }
    }
  }
}
services {
  name = "http-echo"
  port = 9090
  connect {
    sidecar_service {}
  }
}