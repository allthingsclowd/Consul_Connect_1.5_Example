# This is not currently working and requires further debug !!!!!!

## Prerequisites

Clone this repo and perform a vargrant up

e.g.

``` bash
git clone git@github.com:allthingsclowd/Consul_Connect_1.5_Example.git
cd Consul_Connect_1.5_Example
vagrant up
```

This will create a demo consul environment with one consul server (leader01) and two consul clients (app01 & client01).

The following service configuration has been preconfigured on Consul

``` hcl
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
```

# Configure the application service and clients once Consul is booted

``` bash
consul members
Node      Address             Status  Type    Build  Protocol  DC               Segment
leader01  192.168.2.11:8301   alive   server  1.5.0  2         allthingscloud1  <all>
app01     192.168.2.101:8301  alive   client  1.5.0  2         allthingscloud1  <default>
client01  192.168.2.201:8301  alive   client  1.5.0  2         allthingscloud1  <default>
```

The Consul dashboard should look like this ![image](https://user-images.githubusercontent.com/9472095/58022030-77b5ce80-7b04-11e9-99d4-f73bdc674051.png)

## Let's start the demo application

Login to the app01 and run the `http-echo` application in the background remembering to set the application port to 9090 as follows:

``` bash
vagrant ssh app01
http-echo -listen="127.0.0.1:9090" -text="Hello from ${HOSTNAME} application server!" &

2019/05/20 11:15:33 Server is listening on 127.0.0.1:9090
```

Run a quick test as follows:

``` bash
curl http://127.0.0.1:9090

Hello from app01 application server!
```

So we now have a working demo http application that we are going to secure using consul connect.

## Create the proxy that will be used to securely route the application traffic

First let's check that the consul bootstrap process is working by simply requesting the bootstrap file but not actually starting the service...

``` bash
/usr/local/bin/consul connect envoy -http-addr=https://127.0.0.1:8321 -ca-file=/usr/local/bootstrap/certificate-config/consul-ca.pem -client-cert=/usr/local/bootstrap/certificate-config/cli.pem -client-key=/usr/local/bootstrap/certificate-config/cli-key.pem -token=d9c1de45-6a1d-e133-7d0c-5f5756252918 -sidecar-for http-echo -bootstrap
```

and the response will look something like this

``` json
{
  "admin": {
    "access_log_path": "/dev/null",
    "address": {
      "socket_address": {
        "address": "127.0.0.1",
        "port_value": 19000
      }
    }
  },
  "node": {
    "cluster": "http-echo",
    "id": "http-echo-sidecar-proxy"
  },
  "static_resources": {
    "clusters": [
      {
        "name": "local_agent",
        "connect_timeout": "1s",
        "type": "STATIC",
        "http2_protocol_options": {},
        "hosts": [
          {
            "socket_address": {
              "address": "127.0.0.1",
              "port_value": 8502
            }
          }
        ]
      }
    ]
  },
  "stats_config": {
                        "stats_tags": [
                                {
                        "tag_name": "local_cluster",
                        "fixed_value": "http-echo"
                }
                        ],
                        "use_all_default_tags": true
                },
  "dynamic_resources": {
    "lds_config": { "ads": {} },
    "cds_config": { "ads": {} },
    "ads_config": {
      "api_type": "GRPC",
      "grpc_services": {
        "initial_metadata": [
          {
            "key": "x-consul-token",
            "value": "d9c1de45-6a1d-e133-7d0c-5f5756252918"
          }
        ],
        "envoy_grpc": {
          "cluster_name": "local_agent"
        }
      }
    }
  }
```

Now that we can see we're getting the configured bootstrap information we're going to launch an envoy proxy this time by removing the `-bootstrap` option. I'm also going to add the `-- -l debug` to this session so that we can see what's happening - not required during normal operation

``` bash
/usr/local/bin/consul connect envoy -http-addr=https://127.0.0.1:8321 -ca-file=/usr/local/bootstrap/certificate-config/consul-ca.pem -client-cert=/usr/local/bootstrap/certificate-config/cli.pem -client-key=/usr/local/bootstrap/certificate-config/cli-key.pem -token=d9c1de45-6a1d-e133-7d0c-5f5756252918 -sidecar-for http-echo -- -l debug &
```

and we get a lot of scary information like this

``` bash
/usr/local/bin/consul connect envoy -http-addr=https://127.0.0.1:8321 -ca-file=/usr/local/bootstrap/certificate-config/consul-ca.pem -client-cert=/usr/local/bootstrap/certificate-config/cli.pem -client-key=/usr/local/bootstrap/certificate-config/cli-key.pem -token=d9c1de45-6a1d-e133-7d0c-5f5756252918 -sidecar-for http-echo -- -l debug &
[2] 1798
vagrant@app01:~$ [2019-05-20 11:33:44.178][001798][info][main] [source/server/server.cc:206] initializing epoch 0 (hot restart version=disabled)
[2019-05-20 11:33:44.179][001798][info][main] [source/server/server.cc:208] statically linked extensions:
[2019-05-20 11:33:44.179][001798][info][main] [source/server/server.cc:210]   access_loggers: envoy.file_access_log,envoy.http_grpc_access_log
[2019-05-20 11:33:44.180][001798][info][main] [source/server/server.cc:213]   filters.http: envoy.buffer,envoy.cors,envoy.ext_authz,envoy.fault,envoy.filters.http.header_to_metadata,envoy.filters.http.jwt_authn,envoy.filters.http.rbac,envoy.grpc_http1_bridge,envoy.grpc_json_transcoder,envoy.grpc_web,envoy.gzip,envoy.health_check,envoy.http_dynamo_filter,envoy.ip_tagging,envoy.lua,envoy.rate_limit,envoy.router,envoy.squash
[2019-05-20 11:33:44.180][001798][info][main] [source/server/server.cc:216]   filters.listener: envoy.listener.original_dst,envoy.listener.proxy_protocol,envoy.listener.tls_inspector
[2019-05-20 11:33:44.181][001798][info][main] [source/server/server.cc:219]   filters.network: envoy.client_ssl_auth,envoy.echo,envoy.ext_authz,envoy.filters.network.dubbo_proxy,envoy.filters.network.rbac,envoy.filters.network.sni_cluster,envoy.filters.network.thrift_proxy,envoy.http_connection_manager,envoy.mongo_proxy,envoy.ratelimit,envoy.redis_proxy,envoy.tcp_proxy
[2019-05-20 11:33:44.181][001798][info][main] [source/server/server.cc:221]   stat_sinks: envoy.dog_statsd,envoy.metrics_service,envoy.stat_sinks.hystrix,envoy.statsd
[2019-05-20 11:33:44.182][001798][info][main] [source/server/server.cc:223]   tracers: envoy.dynamic.ot,envoy.lightstep,envoy.tracers.datadog,envoy.zipkin
[2019-05-20 11:33:44.182][001798][info][main] [source/server/server.cc:226]   transport_sockets.downstream: envoy.transport_sockets.alts,envoy.transport_sockets.capture,raw_buffer,tls
[2019-05-20 11:33:44.182][001798][info][main] [source/server/server.cc:229]   transport_sockets.upstream: envoy.transport_sockets.alts,envoy.transport_sockets.capture,raw_buffer,tls
[2019-05-20 11:33:44.186][001798][info][main] [source/server/server.cc:271] admin address: 127.0.0.1:19000
[2019-05-20 11:33:44.187][001798][debug][main] [source/server/overload_manager_impl.cc:171] No overload action configured for envoy.overload_actions.stop_accepting_connections.
[2019-05-20 11:33:44.188][001798][info][config] [source/server/configuration_impl.cc:50] loading 0 static secret(s)
[2019-05-20 11:33:44.189][001798][info][config] [source/server/configuration_impl.cc:56] loading 1 cluster(s)
[2019-05-20 11:33:44.192][001810][debug][grpc] [source/common/grpc/google_async_client_impl.cc:41] completionThread running
[2019-05-20 11:33:44.193][001798][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:824] adding TLS initial cluster local_agent
[2019-05-20 11:33:44.199][001798][debug][upstream] [source/common/upstream/upstream_impl.cc:634] initializing secondary cluster local_agent completed
[2019-05-20 11:33:44.199][001798][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:958] membership update for TLS cluster local_agent added 1 removed 0
[2019-05-20 11:33:44.199][001798][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:91] cm init: init complete: cluster=local_agent primary=0 secondary=0
[2019-05-20 11:33:44.200][001798][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:63] cm init: adding: cluster=local_agent primary=0 secondary=0
[2019-05-20 11:33:44.200][001798][info][upstream] [source/common/upstream/cluster_manager_impl.cc:132] cm init: initializing cds
[2019-05-20 11:33:44.200][001798][debug][upstream] [source/common/config/grpc_mux_impl.cc:137] gRPC mux subscribe for type.googleapis.com/envoy.api.v2.Cluster
[2019-05-20 11:33:44.201][001798][debug][upstream] [source/common/config/grpc_mux_impl.cc:89] No stream available to sendDiscoveryRequest for type.googleapis.com/envoy.api.v2.Cluster
[2019-05-20 11:33:44.201][001798][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 11:33:44.204][001798][debug][router] [source/common/router/router.cc:270] [C0][S13761416037249398595] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 11:33:44.205][001798][debug][router] [source/common/router/router.cc:328] [C0][S13761416037249398595] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 11:33:44.208][001798][debug][client] [source/common/http/codec_client.cc:26] [C0] connecting
[2019-05-20 11:33:44.208][001798][debug][connection] [source/common/network/connection_impl.cc:634] [C0] connecting to 127.0.0.1:8502
[2019-05-20 11:33:44.208][001798][debug][connection] [source/common/network/connection_impl.cc:643] [C0] connection in progress
[2019-05-20 11:33:44.208][001798][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C0] setting stream-level initial window size to 268435456
[2019-05-20 11:33:44.208][001798][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C0] updating connection-level initial window size to 268435456
[2019-05-20 11:33:44.208][001798][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 11:33:44.208][001798][info][config] [source/server/configuration_impl.cc:67] loading 0 listener(s)
[2019-05-20 11:33:44.209][001798][info][config] [source/server/configuration_impl.cc:92] loading tracing configuration
[2019-05-20 11:33:44.209][001798][info][config] [source/server/configuration_impl.cc:112] loading stats sink configuration
[2019-05-20 11:33:44.209][001798][info][main] [source/server/server.cc:463] starting main dispatch loop
[2019-05-20 11:33:44.209][001798][debug][connection] [source/common/network/connection_impl.cc:525] [C0] delayed connection error: 111
[2019-05-20 11:33:44.209][001798][debug][connection] [source/common/network/connection_impl.cc:183] [C0] closing socket: 0
[2019-05-20 11:33:44.209][001798][debug][client] [source/common/http/codec_client.cc:82] [C0] disconnect. resetting 0 pending requests
[2019-05-20 11:33:44.209][001798][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C0] client disconnected
[2019-05-20 11:33:44.209][001798][debug][router] [source/common/router/router.cc:481] [C0][S13761416037249398595] upstream reset
[2019-05-20 11:33:44.209][001798][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 11:33:44.209][001798][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 11:33:44.210][001798][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C0] destroying primary client
[2019-05-20 11:33:44.687][001798][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 11:33:44.687][001798][debug][router] [source/common/router/router.cc:270] [C0][S17501570533820117116] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 11:33:44.687][001798][debug][router] [source/common/router/router.cc:328] [C0][S17501570533820117116] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 11:33:44.687][001798][debug][client] [source/common/http/codec_client.cc:26] [C1] connecting
[2019-05-20 11:33:44.687][001798][debug][connection] [source/common/network/connection_impl.cc:634] [C1] connecting to 127.0.0.1:8502
[2019-05-20 11:33:44.687][001798][debug][connection] [source/common/network/connection_impl.cc:643] [C1] connection in progress
[2019-05-20 11:33:44.688][001798][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C1] setting stream-level initial window size to 268435456
[2019-05-20 11:33:44.688][001798][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C1] updating connection-level initial window size to 268435456
[2019-05-20 11:33:44.688][001798][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 11:33:44.688][001798][debug][connection] [source/common/network/connection_impl.cc:525] [C1] delayed connection error: 111
[2019-05-20 11:33:44.688][001798][debug][connection] [source/common/network/connection_impl.cc:183] [C1] closing socket: 0
[2019-05-20 11:33:44.688][001798][debug][client] [source/common/http/codec_client.cc:82] [C1] disconnect. resetting 0 pending requests
[2019-05-20 11:33:44.688][001798][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C1] client disconnected
[2019-05-20 11:33:44.688][001798][debug][router] [source/common/router/router.cc:481] [C0][S17501570533820117116] upstream reset
[2019-05-20 11:33:44.688][001798][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 11:33:44.688][001798][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 11:33:44.688][001798][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C1] destroying primary client
[2019-05-20 11:33:45.785][001798][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 11:33:45.786][001798][debug][router] [source/common/router/router.cc:270] [C0][S12477858197134802256] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 11:33:45.786][001798][debug][router] [source/common/router/router.cc:328] [C0][S12477858197134802256] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 11:33:45.786][001798][debug][client] [source/common/http/codec_client.cc:26] [C2] connecting
[2019-05-20 11:33:45.786][001798][debug][connection] [source/common/network/connection_impl.cc:634] [C2] connecting to 127.0.0.1:8502
[2019-05-20 11:33:45.786][001798][debug][connection] [source/common/network/connection_impl.cc:643] [C2] connection in progress
[2019-05-20 11:33:45.786][001798][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C2] setting stream-level initial window size to 268435456
[2019-05-20 11:33:45.786][001798][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C2] updating connection-level initial window size to 268435456
[2019-05-20 11:33:45.786][001798][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 11:33:45.786][001798][debug][connection] [source/common/network/connection_impl.cc:525] [C2] delayed connection error: 111
[2019-05-20 11:33:45.786][001798][debug][connection] [source/common/network/connection_impl.cc:183] [C2] closing socket: 0
[2019-05-20 11:33:45.786][001798][debug][client] [source/common/http/codec_client.cc:82] [C2] disconnect. resetting 0 pending requests
[2019-05-20 11:33:45.786][001798][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C2] client disconnected
[2019-05-20 11:33:45.786][001798][debug][router] [source/common/router/router.cc:481] [C0][S12477858197134802256] upstream reset
[2019-05-20 11:33:45.786][001798][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 11:33:45.786][001798][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 11:33:45.786][001798][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C2] destroying primary client
[2019-05-20 11:33:45.992][001798][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 11:33:45.993][001798][debug][router] [source/common/router/router.cc:270] [C0][S11209790984730619480] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 11:33:45.993][001798][debug][router] [source/common/router/router.cc:328] [C0][S11209790984730619480] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 11:33:45.993][001798][debug][client] [source/common/http/codec_client.cc:26] [C3] connecting
[2019-05-20 11:33:45.994][001798][debug][connection] [source/common/network/connection_impl.cc:634] [C3] connecting to 127.0.0.1:8502
[2019-05-20 11:33:45.994][001798][debug][connection] [source/common/network/connection_impl.cc:643] [C3] connection in progress
[2019-05-20 11:33:45.994][001798][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C3] setting stream-level initial window size to 268435456
[2019-05-20 11:33:45.994][001798][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C3] updating connection-level initial window size to 268435456
[2019-05-20 11:33:45.994][001798][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 11:33:45.994][001798][debug][connection] [source/common/network/connection_impl.cc:525] [C3] delayed connection error: 111
[2019-05-20 11:33:45.994][001798][debug][connection] [source/common/network/connection_impl.cc:183] [C3] closing socket: 0
[2019-05-20 11:33:45.994][001798][debug][client] [source/common/http/codec_client.cc:82] [C3] disconnect. resetting 0 pending requests
[2019-05-20 11:33:45.994][001798][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C3] client disconnected
[2019-05-20 11:33:45.994][001798][debug][router] [source/common/router/router.cc:481] [C0][S11209790984730619480] upstream reset
[2019-05-20 11:33:45.994][001798][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 11:33:45.994][001798][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 11:33:45.994][001798][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C3] destroying primary client
[2019-05-20 11:33:49.208][001798][debug][main] [source/server/server.cc:143] flushing stats
[2019-05-20 11:33:51.922][001798][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 11:33:51.923][001798][debug][router] [source/common/router/router.cc:270] [C0][S8343631571160884213] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 11:33:51.923][001798][debug][router] [source/common/router/router.cc:328] [C0][S8343631571160884213] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 11:33:51.923][001798][debug][client] [source/common/http/codec_client.cc:26] [C4] connecting
[2019-05-20 11:33:51.923][001798][debug][connection] [source/common/network/connection_impl.cc:634] [C4] connecting to 127.0.0.1:8502
[2019-05-20 11:33:51.923][001798][debug][connection] [source/common/network/connection_impl.cc:643] [C4] connection in progress
[2019-05-20 11:33:51.923][001798][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C4] setting stream-level initial window size to 268435456
[2019-05-20 11:33:51.923][001798][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C4] updating connection-level initial window size to 268435456
[2019-05-20 11:33:51.923][001798][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 11:33:51.923][001798][debug][connection] [source/common/network/connection_impl.cc:525] [C4] delayed connection error: 111
[2019-05-20 11:33:51.923][001798][debug][connection] [source/common/network/connection_impl.cc:183] [C4] closing socket: 0
[2019-05-20 11:33:51.923][001798][debug][client] [source/common/http/codec_client.cc:82] [C4] disconnect. resetting 0 pending requests
[2019-05-20 11:33:51.923][001798][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C4] client disconnected
[2019-05-20 11:33:51.923][001798][debug][router] [source/common/router/router.cc:481] [C0][S8343631571160884213] upstream reset
[2019-05-20 11:33:51.923][001798][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 11:33:51.923][001798][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 11:33:51.923][001798][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C4] destroying primary client
[2019-05-20 11:34:05.222][001798][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 11:34:05.222][001798][debug][router] [source/common/router/router.cc:270] [C0][S12242718444513648944] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 11:34:05.222][001798][debug][router] [source/common/router/router.cc:328] [C0][S12242718444513648944] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 11:34:05.222][001798][debug][client] [source/common/http/codec_client.cc:26] [C5] connecting
[2019-05-20 11:34:05.222][001798][debug][connection] [source/common/network/connection_impl.cc:634] [C5] connecting to 127.0.0.1:8502
[2019-05-20 11:34:05.222][001798][debug][connection] [source/common/network/connection_impl.cc:643] [C5] connection in progress
[2019-05-20 11:34:05.222][001798][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C5] setting stream-level initial window size to 268435456
[2019-05-20 11:34:05.222][001798][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C5] updating connection-level initial window size to 268435456
[2019-05-20 11:34:05.222][001798][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 11:34:05.222][001798][debug][connection] [source/common/network/connection_impl.cc:525] [C5] delayed connection error: 111
[2019-05-20 11:34:05.222][001798][debug][connection] [source/common/network/connection_impl.cc:183] [C5] closing socket: 0
[2019-05-20 11:34:05.222][001798][debug][client] [source/common/http/codec_client.cc:82] [C5] disconnect. resetting 0 pending requests
[2019-05-20 11:34:05.222][001798][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C5] client disconnected
[2019-05-20 11:34:05.222][001798][debug][router] [source/common/router/router.cc:481] [C0][S12242718444513648944] upstream reset
[2019-05-20 11:34:05.222][001798][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 11:34:05.222][001798][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 11:34:05.222][001798][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C5] destroying primary client
[2019-05-20 11:34:26.334][001798][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 11:34:26.334][001798][debug][router] [source/common/router/router.cc:270] [C0][S15706465528168710374] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 11:34:26.334][001798][debug][router] [source/common/router/router.cc:328] [C0][S15706465528168710374] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 11:34:26.334][001798][debug][client] [source/common/http/codec_client.cc:26] [C6] connecting
[2019-05-20 11:34:26.334][001798][debug][connection] [source/common/network/connection_impl.cc:634] [C6] connecting to 127.0.0.1:8502
[2019-05-20 11:34:26.334][001798][debug][connection] [source/common/network/connection_impl.cc:643] [C6] connection in progress
[2019-05-20 11:34:26.334][001798][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C6] setting stream-level initial window size to 268435456
[2019-05-20 11:34:26.334][001798][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C6] updating connection-level initial window size to 268435456
[2019-05-20 11:34:26.334][001798][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 11:34:26.334][001798][debug][connection] [source/common/network/connection_impl.cc:525] [C6] delayed connection error: 111
[2019-05-20 11:34:26.334][001798][debug][connection] [source/common/network/connection_impl.cc:183] [C6] closing socket: 0
[2019-05-20 11:34:26.334][001798][debug][client] [source/common/http/codec_client.cc:82] [C6] disconnect. resetting 0 pending requests
[2019-05-20 11:34:26.334][001798][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C6] client disconnected
[2019-05-20 11:34:26.334][001798][debug][router] [source/common/router/router.cc:481] [C0][S15706465528168710374] upstream reset
[2019-05-20 11:34:26.334][001798][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 11:34:26.334][001798][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 11:34curl http://127.0.0.1:9090[2019-05-20 11:34:34.656][001798][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 11:34:34.656][001798][debug][router] [source/common/router/router.cc:270] [C0][S14094017419280731881] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 11:34:34.656][001798][debug][router] [source/common/router/router.cc:328] [C0][S14094017419280731881] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 11:34:34.656][001798][debug][client] [source/common/http/codec_client.cc:26] [C7] connecting
[2019-05-20 11:34:34.656][001798][debug][connection] [source/common/network/connection_impl.cc:634] [C7] connecting to 127.0.0.1:8502
[2019-05-20 11:34:34.656][001798][debug][connection] [source/common/network/connection_impl.cc:643] [C7] connection in progress
[2019-05-20 11:34:34.656][001798][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C7] setting stream-level initial window size to 268435456
[2019-05-20 11:34:34.656][001798][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C7] updating connection-level initial window size to 268435456
[2019-05-20 11:34:34.656][001798][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 11:34:34.656][001798][debug][connection] [source/common/network/connection_impl.cc:525] [C7] delayed connection error: 111
[2019-05-20 11:34:34.656][001798][debug][connection] [source/common/network/connection_impl.cc:183] [C7] closing socket: 0
[2019-05-20 11:34:34.656][001798][debug][client] [source/common/http/codec_client.cc:82] [C7] disconnect. resetting 0 pending requests
[2019-05-20 11:34:34.656][001798][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C7] client disconnected
[2019-05-20 11:34:34.656][001798][debug][router] [source/common/router/router.cc:481] [C0][S14094017419280731881] upstream reset
[2019-05-20 11:34:34.656][001798][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 11:34:34.656][001798][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 11:34:34.656][001798][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C7] destroying primary client
```

It's also possible to query the envoy configuration by using envoy's admin interface 

``` bash
curl localhost:19000/config_dump
```

and then we can see the following configuration returned

``` json
{
 "configs": [
  {
   "@type": "type.googleapis.com/envoy.admin.v2alpha.BootstrapConfigDump",
   "bootstrap": {
    "node": {
     "id": "http-echo-sidecar-proxy",
     "cluster": "http-echo",
     "build_version": "ea248e2919db841b4f3cc5e2c44dcbd90565467d/1.9.1/Clean/RELEASE/BoringSSL"
    },
    "static_resources": {
     "clusters": [
      {
       "name": "local_agent",
       "connect_timeout": "1s",
       "hosts": [
        {
         "socket_address": {
          "address": "127.0.0.1",
          "port_value": 8502
         }
        }
       ],
       "http2_protocol_options": {}
      }
     ]
    },
    "dynamic_resources": {
     "lds_config": {
      "ads": {}
     },
     "cds_config": {
      "ads": {}
     },
     "ads_config": {
      "api_type": "GRPC",
      "grpc_services": [
       {
        "envoy_grpc": {
         "cluster_name": "local_agent"
        },
        "initial_metadata": [
         {
          "key": "x-consul-token",
          "value": "d9c1de45-6a1d-e133-7d0c-5f5756252918"
         }
        ]
       }
      ]
     }
    },
    "admin": {
     "access_log_path": "/dev/null",
     "address": {
      "socket_address": {
       "address": "127.0.0.1",
       "port_value": 19000
      }
     }
    },
    "stats_config": {
     "stats_tags": [
      {
       "tag_name": "local_cluster",
       "fixed_value": "http-echo"
      }
     ],
     "use_all_default_tags": true
    }
   },
   "last_updated": "2019-05-20T11:33:44.185Z"
  },
  {
   "@type": "type.googleapis.com/envoy.admin.v2alpha.ClustersConfigDump",
   "static_clusters": [
    {
     "cluster": {
      "name": "local_agent",
      "connect_timeout": "1s",
      "hosts": [
       {
        "socket_address": {
         "address": "127.0.0.1",
         "port_value": 8502
        }
       }
      ],
      "http2_protocol_options": {}
     },
     "last_updated": "2019-05-20T11:33:44.193Z"
    }
   ]
  },
  {
   "@type": "type.googleapis.com/envoy.admin.v2alpha.ListenersConfigDump"
  }
 ]
```

_[Note-to-self :at this point the app sidecar proxy still shows as failing in Consul this maybe broken - I tried creating intentions between both client and http-echo service but this has made no difference]_

## Now we'll jump over to the client node and start the client proxy service

``` bash
exit
vagrant ssh client01
```

Let's quickly verify what the consul envoy bootstrap config looks like for this proxy

``` bash
/usr/local/bin/consul connect envoy -http-addr=https://127.0.0.1:8321 -ca-file=/usr/local/bootstrap/certificate-config/consul-ca.pem -client-cert=/usr/local/bootstrap/certificate-config/cli.pem -client-key=/usr/local/bootstrap/certificate-config/cli-key.pem -token=d9c1de45-6a1d-e133-7d0c-5f5756252918 -sidecar-for client -bootstrap
```

and we get

``` json
{
  "admin": {
    "access_log_path": "/dev/null",
    "address": {
      "socket_address": {
        "address": "127.0.0.1",
        "port_value": 19000
      }
    }
  },
  "node": {
    "cluster": "client",
    "id": "client-sidecar-proxy"
  },
  "static_resources": {
    "clusters": [
      {
        "name": "local_agent",
        "connect_timeout": "1s",
        "type": "STATIC",
        "http2_protocol_options": {},
        "hosts": [
          {
            "socket_address": {
              "address": "127.0.0.1",
              "port_value": 8502
            }
          }
        ]
      }
    ]
  },
  "stats_config": {
                        "stats_tags": [
                                {
                        "tag_name": "local_cluster",
                        "fixed_value": "client"
                }
                        ],
                        "use_all_default_tags": true
                },
  "dynamic_resources": {
    "lds_config": { "ads": {} },
    "cds_config": { "ads": {} },
    "ads_config": {
      "api_type": "GRPC",
      "grpc_services": {
        "initial_metadata": [
          {
            "key": "x-consul-token",
            "value": "d9c1de45-6a1d-e133-7d0c-5f5756252918"
          }
        ],
        "envoy_grpc": {
          "cluster_name": "local_agent"
        }
      }
    }
  }
}
```

So let apply this again with the envoy debug option set

``` bash
/usr/local/bin/consul connect envoy -http-addr=https://127.0.0.1:8321 -ca-file=/usr/local/bootstrap/certificate-config/consul-ca.pem -client-cert=/usr/local/bootstrap/certificate-config/cli.pem -client-key=/usr/local/bootstrap/certificate-config/cli-key.pem -token=d9c1de45-6a1d-e133-7d0c-5f5756252918 -sidecar-for client -- -l debug &
```

which returns the following logs

``` bash
[2019-05-20 12:03:00.943][001769][info][main] [source/server/server.cc:206] initializing epoch 0 (hot restart version=disabled)
[2019-05-20 12:03:00.943][001769][info][main] [source/server/server.cc:208] statically linked extensions:
[2019-05-20 12:03:00.943][001769][info][main] [source/server/server.cc:210]   access_loggers: envoy.file_access_log,envoy.http_grpc_access_log
[2019-05-20 12:03:00.944][001769][info][main] [source/server/server.cc:213]   filters.http: envoy.buffer,envoy.cors,envoy.ext_authz,envoy.fault,envoy.filters.http.header_to_metadata,envoy.filters.http.jwt_authn,envoy.filters.http.rbac,envoy.grpc_http1_bridge,envoy.grpc_json_transcoder,envoy.grpc_web,envoy.gzip,envoy.health_check,envoy.http_dynamo_filter,envoy.ip_tagging,envoy.lua,envoy.rate_limit,envoy.router,envoy.squash
[2019-05-20 12:03:00.944][001769][info][main] [source/server/server.cc:216]   filters.listener: envoy.listener.original_dst,envoy.listener.proxy_protocol,envoy.listener.tls_inspector
[2019-05-20 12:03:00.944][001769][info][main] [source/server/server.cc:219]   filters.network: envoy.client_ssl_auth,envoy.echo,envoy.ext_authz,envoy.filters.network.dubbo_proxy,envoy.filters.network.rbac,envoy.filters.network.sni_cluster,envoy.filters.network.thrift_proxy,envoy.http_connection_manager,envoy.mongo_proxy,envoy.ratelimit,envoy.redis_proxy,envoy.tcp_proxy
[2019-05-20 12:03:00.945][001769][info][main] [source/server/server.cc:221]   stat_sinks: envoy.dog_statsd,envoy.metrics_service,envoy.stat_sinks.hystrix,envoy.statsd
[2019-05-20 12:03:00.946][001769][info][main] [source/server/server.cc:223]   tracers: envoy.dynamic.ot,envoy.lightstep,envoy.tracers.datadog,envoy.zipkin
[2019-05-20 12:03:00.946][001769][info][main] [source/server/server.cc:226]   transport_sockets.downstream: envoy.transport_sockets.alts,envoy.transport_sockets.capture,raw_buffer,tls
[2019-05-20 12:03:00.946][001769][info][main] [source/server/server.cc:229]   transport_sockets.upstream: envoy.transport_sockets.alts,envoy.transport_sockets.capture,raw_buffer,tls
[2019-05-20 12:03:00.951][001769][info][main] [source/server/server.cc:271] admin address: 127.0.0.1:19000
[2019-05-20 12:03:00.952][001769][debug][main] [source/server/overload_manager_impl.cc:171] No overload action configured for envoy.overload_actions.stop_accepting_connections.
[2019-05-20 12:03:00.954][001769][info][config] [source/server/configuration_impl.cc:50] loading 0 static secret(s)
[2019-05-20 12:03:00.954][001769][info][config] [source/server/configuration_impl.cc:56] loading 1 cluster(s)
[2019-05-20 12:03:00.960][001781][debug][grpc] [source/common/grpc/google_async_client_impl.cc:41] completionThread running
[2019-05-20 12:03:00.961][001769][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:824] adding TLS initial cluster local_agent
[2019-05-20 12:03:00.966][001769][debug][upstream] [source/common/upstream/upstream_impl.cc:634] initializing secondary cluster local_agent completed
[2019-05-20 12:03:00.966][001769][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:958] membership update for TLS cluster local_agent added 1 removed 0
[2019-05-20 12:03:00.967][001769][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:91] cm init: init complete: cluster=local_agent primary=0 secondary=0
[2019-05-20 12:03:00.967][001769][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:63] cm init: adding: cluster=local_agent primary=0 secondary=0
[2019-05-20 12:03:00.967][001769][info][upstream] [source/common/upstream/cluster_manager_impl.cc:132] cm init: initializing cds
[2019-05-20 12:03:00.968][001769][debug][upstream] [source/common/config/grpc_mux_impl.cc:137] gRPC mux subscribe for type.googleapis.com/envoy.api.v2.Cluster
[2019-05-20 12:03:00.968][001769][debug][upstream] [source/common/config/grpc_mux_impl.cc:89] No stream available to sendDiscoveryRequest for type.googleapis.com/envoy.api.v2.Cluster
[2019-05-20 12:03:00.969][001769][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 12:03:00.972][001769][debug][router] [source/common/router/router.cc:270] [C0][S4386322937912615926] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 12:03:00.972][001769][debug][router] [source/common/router/router.cc:328] [C0][S4386322937912615926] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 12:03:00.975][001769][debug][client] [source/common/http/codec_client.cc:26] [C0] connecting
[2019-05-20 12:03:00.975][001769][debug][connection] [source/common/network/connection_impl.cc:634] [C0] connecting to 127.0.0.1:8502
[2019-05-20 12:03:00.975][001769][debug][connection] [source/common/network/connection_impl.cc:643] [C0] connection in progress
[2019-05-20 12:03:00.976][001769][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C0] setting stream-level initial window size to 268435456
[2019-05-20 12:03:00.976][001769][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C0] updating connection-level initial window size to 268435456
[2019-05-20 12:03:00.976][001769][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 12:03:00.976][001769][info][config] [source/server/configuration_impl.cc:67] loading 0 listener(s)
[2019-05-20 12:03:00.976][001769][info][config] [source/server/configuration_impl.cc:92] loading tracing configuration
[2019-05-20 12:03:00.976][001769][info][config] [source/server/configuration_impl.cc:112] loading stats sink configuration
[2019-05-20 12:03:00.976][001769][info][main] [source/server/server.cc:463] starting main dispatch loop
[2019-05-20 12:03:00.976][001769][debug][connection] [source/common/network/connection_impl.cc:525] [C0] delayed connection error: 111
[2019-05-20 12:03:00.977][001769][debug][connection] [source/common/network/connection_impl.cc:183] [C0] closing socket: 0
[2019-05-20 12:03:00.977][001769][debug][client] [source/common/http/codec_client.cc:82] [C0] disconnect. resetting 0 pending requests
[2019-05-20 12:03:00.977][001769][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C0] client disconnected
[2019-05-20 12:03:00.977][001769][debug][router] [source/common/router/router.cc:481] [C0][S4386322937912615926] upstream reset
[2019-05-20 12:03:00.977][001769][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 12:03:00.977][001769][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 12:03:00.977][001769][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C0] destroying primary client
[2019-05-20 12:03:01.389][001769][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 12:03:01.390][001769][debug][router] [source/common/router/router.cc:270] [C0][S5811139141233596751] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 12:03:01.390][001769][debug][router] [source/common/router/router.cc:328] [C0][S5811139141233596751] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 12:03:01.391][001769][debug][client] [source/common/http/codec_client.cc:26] [C1] connecting
[2019-05-20 12:03:01.391][001769][debug][connection] [source/common/network/connection_impl.cc:634] [C1] connecting to 127.0.0.1:8502
[2019-05-20 12:03:01.391][001769][debug][connection] [source/common/network/connection_impl.cc:643] [C1] connection in progress
[2019-05-20 12:03:01.391][001769][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C1] setting stream-level initial window size to 268435456
[2019-05-20 12:03:01.391][001769][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C1] updating connection-level initial window size to 268435456
[2019-05-20 12:03:01.391][001769][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 12:03:01.391][001769][debug][connection] [source/common/network/connection_impl.cc:525] [C1] delayed connection error: 111
[2019-05-20 12:03:01.392][001769][debug][connection] [source/common/network/connection_impl.cc:183] [C1] closing socket: 0
[2019-05-20 12:03:01.392][001769][debug][client] [source/common/http/codec_client.cc:82] [C1] disconnect. resetting 0 pending requests
[2019-05-20 12:03:01.392][001769][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C1] client disconnected
[2019-05-20 12:03:01.392][001769][debug][router] [source/common/router/router.cc:481] [C0][S5811139141233596751] upstream reset
[2019-05-20 12:03:01.392][001769][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 12:03:01.392][001769][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 12:03:01.392][001769][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C1] destroying primary client
[2019-05-20 12:03:01.998][001769][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 12:03:01.998][001769][debug][router] [source/common/router/router.cc:270] [C0][S16186795913244686887] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 12:03:01.998][001769][debug][router] [source/common/router/router.cc:328] [C0][S16186795913244686887] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 12:03:01.998][001769][debug][client] [source/common/http/codec_client.cc:26] [C2] connecting
[2019-05-20 12:03:01.998][001769][debug][connection] [source/common/network/connection_impl.cc:634] [C2] connecting to 127.0.0.1:8502
[2019-05-20 12:03:01.998][001769][debug][connection] [source/common/network/connection_impl.cc:643] [C2] connection in progress
[2019-05-20 12:03:01.998][001769][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C2] setting stream-level initial window size to 268435456
[2019-05-20 12:03:01.998][001769][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C2] updating connection-level initial window size to 268435456
[2019-05-20 12:03:01.998][001769][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 12:03:01.998][001769][debug][connection] [source/common/network/connection_impl.cc:525] [C2] delayed connection error: 111
[2019-05-20 12:03:01.998][001769][debug][connection] [source/common/network/connection_impl.cc:183] [C2] closing socket: 0
[2019-05-20 12:03:01.998][001769][debug][client] [source/common/http/codec_client.cc:82] [C2] disconnect. resetting 0 pending requests
[2019-05-20 12:03:01.999][001769][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C2] client disconnected
[2019-05-20 12:03:01.999][001769][debug][router] [source/common/router/router.cc:481] [C0][S16186795913244686887] upstream reset
[2019-05-20 12:03:01.999][001769][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 12:03:01.999][001769][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 12:03:01.999][001769][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C2] destroying primary client
[2019-05-20 12:03:02.014][001769][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 12:03:02.014][001769][debug][router] [source/common/router/router.cc:270] [C0][S18197150098957735351] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 12:03:02.014][001769][debug][router] [source/common/router/router.cc:328] [C0][S18197150098957735351] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 12:03:02.014][001769][debug][client] [source/common/http/codec_client.cc:26] [C3] connecting
[2019-05-20 12:03:02.014][001769][debug][connection] [source/common/network/connection_impl.cc:634] [C3] connecting to 127.0.0.1:8502
[2019-05-20 12:03:02.014][001769][debug][connection] [source/common/network/connection_impl.cc:643] [C3] connection in progress
[2019-05-20 12:03:02.015][001769][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C3] setting stream-level initial window size to 268435456
[2019-05-20 12:03:02.015][001769][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C3] updating connection-level initial window size to 268435456
[2019-05-20 12:03:02.015][001769][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 12:03:02.015][001769][debug][connection] [source/common/network/connection_impl.cc:525] [C3] delayed connection error: 111
[2019-05-20 12:03:02.015][001769][debug][connection] [source/common/network/connection_impl.cc:183] [C3] closing socket: 0
[2019-05-20 12:03:02.015][001769][debug][client] [source/common/http/codec_client.cc:82] [C3] disconnect. resetting 0 pending requests
[2019-05-20 12:03:02.015][001769][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C3] client disconnected
[2019-05-20 12:03:02.015][001769][debug][router] [source/common/router/router.cc:481] [C0][S18197150098957735351] upstream reset
[2019-05-20 12:03:02.015][001769][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 12:03:02.015][001769][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 12:03:02.015][001769][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C3] destroying primary client
[2019-05-20 12:03:02.602][001769][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 12:03:02.603][001769][debug][router] [source/common/router/router.cc:270] [C0][S14043247831324705376] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 12:03:02.603][001769][debug][router] [source/common/router/router.cc:328] [C0][S14043247831324705376] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 12:03:02.603][001769][debug][client] [source/common/http/codec_client.cc:26] [C4] connecting
[2019-05-20 12:03:02.603][001769][debug][connection] [source/common/network/connection_impl.cc:634] [C4] connecting to 127.0.0.1:8502
[2019-05-20 12:03:02.603][001769][debug][connection] [source/common/network/connection_impl.cc:643] [C4] connection in progress
[2019-05-20 12:03:02.603][001769][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C4] setting stream-level initial window size to 268435456
[2019-05-20 12:03:02.603][001769][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C4] updating connection-level initial window size to 268435456
[2019-05-20 12:03:02.604][001769][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 12:03:02.604][001769][debug][connection] [source/common/network/connection_impl.cc:525] [C4] delayed connection error: 111
[2019-05-20 12:03:02.604][001769][debug][connection] [source/common/network/connection_impl.cc:183] [C4] closing socket: 0
[2019-05-20 12:03:02.604][001769][debug][client] [source/common/http/codec_client.cc:82] [C4] disconnect. resetting 0 pending requests
[2019-05-20 12:03:02.604][001769][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C4] client disconnected
[2019-05-20 12:03:02.604][001769][debug][router] [source/common/router/router.cc:481] [C0][S14043247831324705376] upstream reset
[2019-05-20 12:03:02.604][001769][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 12:03:02.604][001769][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 12:03:02.604][001769][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C4] destroying primary client
[2019-05-20 12:03:03.652][001769][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-20 12:03:03.652][001769][debug][router] [source/common/router/router.cc:270] [C0][S7118096690476843949] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-20 12:03:03.652][001769][debug][router] [source/common/router/router.cc:328] [C0][S7118096690476843949] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'd9c1de45-6a1d-e133-7d0c-5f5756252918'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-20 12:03:03.652][001769][debug][client] [source/common/http/codec_client.cc:26] [C5] connecting
[2019-05-20 12:03:03.652][001769][debug][connection] [source/common/network/connection_impl.cc:634] [C5] connecting to 127.0.0.1:8502
[2019-05-20 12:03:03.652][001769][debug][connection] [source/common/network/connection_impl.cc:643] [C5] connection in progress
[2019-05-20 12:03:03.652][001769][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C5] setting stream-level initial window size to 268435456
[2019-05-20 12:03:03.652][001769][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C5] updating connection-level initial window size to 268435456
[2019-05-20 12:03:03.652][001769][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-20 12:03:03.652][001769][debug][connection] [source/common/network/connection_impl.cc:525] [C5] delayed connection error: 111
[2019-05-20 12:03:03.652][001769][debug][connection] [source/common/network/connection_impl.cc:183] [C5] closing socket: 0
[2019-05-20 12:03:03.652][001769][debug][client] [source/common/http/codec_client.cc:82] [C5] disconnect. resetting 0 pending requests
[2019-05-20 12:03:03.652][001769][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C5] client disconnected
[2019-05-20 12:03:03.652][001769][debug][router] [source/common/router/router.cc:481] [C0][S7118096690476843949] upstream reset
[2019-05-20 12:03:03.652][001769][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-20 12:03:03.652][001769][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-20 12:03:03.652][001769][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C5] destroying primary client
[[2019-05-20 12:03:05.974][001769][debug][main] [source/server/server.cc:143] flushing stats
```

And the envoy proxy client configuration looks like this

``` bash
curl localhost:19000/config_dump
```

returns

``` json
{
 "configs": [
  {
   "@type": "type.googleapis.com/envoy.admin.v2alpha.BootstrapConfigDump",
   "bootstrap": {
    "node": {
     "id": "client-sidecar-proxy",
     "cluster": "client",
     "build_version": "ea248e2919db841b4f3cc5e2c44dcbd90565467d/1.9.1/Clean/RELEASE/BoringSSL"
    },
    "static_resources": {
     "clusters": [
      {
       "name": "local_agent",
       "connect_timeout": "1s",
       "hosts": [
        {
         "socket_address": {
          "address": "127.0.0.1",
          "port_value": 8502
         }
        }
       ],
       "http2_protocol_options": {}
      }
     ]
    },
    "dynamic_resources": {
     "lds_config": {
      "ads": {}
     },
     "cds_config": {
      "ads": {}
     },
     "ads_config": {
      "api_type": "GRPC",
      "grpc_services": [
       {
        "envoy_grpc": {
         "cluster_name": "local_agent"
        },
        "initial_metadata": [
         {
          "key": "x-consul-token",
          "value": "d9c1de45-6a1d-e133-7d0c-5f5756252918"
         }
        ]
       }
      ]
     }
    },
    "admin": {
     "access_log_path": "/dev/null",
     "address": {
      "socket_address": {
       "address": "127.0.0.1",
       "port_value": 19000
      }
     }
    },
    "stats_config": {
     "stats_tags": [
      {
       "tag_name": "local_cluster",
       "fixed_value": "client"
      }
     ],
     "use_all_default_tags": true
    }
   },
   "last_updated": "2019-05-20T12:03:00.948Z"
  },
  {
   "@type": "type.googleapis.com/envoy.admin.v2alpha.ClustersConfigDump",
   "static_clusters": [
    {
     "cluster": {
      "name": "local_agent",
      "connect_timeout": "1s",
      "hosts": [
       {
        "socket_address": {
         "address": "127.0.0.1",
         "port_value": 8502
        }
       }
      ],
      "http2_protocol_options": {}
     },
     "last_updated": "2019-05-20T12:03:00.961Z"
    }
   ]
  },
  {
   "@type": "type.googleapis.com/envoy.admin.v2alpha.ListenersConfigDump"
  }
 ]
}
```
## And finally let's test with the client application ... (curl)

On the client node

``` bash
vagrant@client01:~$ curl http://127.0.0.1:1234
curl: (7) Failed to connect to 127.0.0.1 port 1234: Connection refused
vagrant@client01:~$ curl http://localhost:1234
curl: (7) Failed to connect to localhost port 1234: Connection refused
```

# Consul Logs

## Consul server - leader01

```bash
vagrant@leader01:~$ sudo grep -E 'consul|envoy' /var/log/syslog | more
May 20 10:56:10 vagrant consul[1361]: BootstrapExpect is set to 1; this is the same as Bootstrap mode.
May 20 10:56:10 vagrant consul[1361]: bootstrap = true: do not enable unless necessary
May 20 10:56:10 vagrant consul[1361]: ==> Starting Consul agent...
May 20 10:56:10 vagrant consul[1361]: ==> Consul agent running!
May 20 10:56:10 vagrant consul[1361]:            Version: 'v1.5.0'
May 20 10:56:10 vagrant consul[1361]:            Node ID: 'fe893672-44d8-bb7c-0fcb-714f2c329f45'
May 20 10:56:10 vagrant consul[1361]:          Node name: 'leader01'
May 20 10:56:10 vagrant consul[1361]:         Datacenter: 'allthingscloud1' (Segment: '<all>')
May 20 10:56:10 vagrant consul[1361]:             Server: true (Bootstrap: true)
May 20 10:56:10 vagrant consul[1361]:        Client Addr: [127.0.0.1] (HTTP: -1, HTTPS: 8321, gRPC: 8502, DNS: 8600)
May 20 10:56:10 vagrant consul[1361]:       Cluster Addr: 192.168.2.11 (LAN: 8301, WAN: 8302)
May 20 10:56:10 vagrant consul[1361]:            Encrypt: Gossip: false, TLS-Outgoing: true, TLS-Incoming: true
May 20 10:56:10 vagrant consul[1361]: ==> Log data will now stream in as it occurs:
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [DEBUG] agent: Using random ID "fe893672-44d8-bb7c-0fcb-714f2c329f45" as node ID
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [DEBUG] tlsutil: Update with version 1
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [DEBUG] tlsutil: OutgoingRPCWrapper with version 1
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [DEBUG] tlsutil: IncomingRPCConfig with version 1
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [DEBUG] tlsutil: OutgoingRPCWrapper with version 1
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [INFO] raft: Initial configuration (index=1): [{Suffrage:Voter ID:fe893672-44d8-bb7c-0fcb-71
4f2c329f45 Address:192.168.2.11:8300}]
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [INFO] serf: EventMemberJoin: leader01.allthingscloud1 192.168.2.11
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [INFO] serf: EventMemberJoin: leader01 192.168.2.11
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [INFO] raft: Node at 192.168.2.11:8300 [Follower] entering Follower state (Leader: "")
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [INFO] consul: Adding LAN server leader01 (Addr: tcp/192.168.2.11:8300) (DC: allthingscloud1
)
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [INFO] consul: Handled member-join event for server "leader01.allthingscloud1" in area "wan"
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [DEBUG] agent/proxy: managed Connect proxy manager started
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [INFO] agent: Started DNS server 127.0.0.1:8600 (tcp)
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [INFO] agent: Started DNS server 127.0.0.1:8600 (udp)
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [INFO] agent: Started HTTPS server on [::]:8321 (tcp)
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [INFO] agent: started state syncer
May 20 10:56:10 vagrant consul[1361]:     2019/05/20 10:56:10 [INFO] agent: Started gRPC server on 127.0.0.1:8502 (tcp)
May 20 10:56:14 vagrant consul[1361]:     2019/05/20 10:56:14 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [WARN] raft: Heartbeat timeout from "" reached, starting election
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [INFO] raft: Node at 192.168.2.11:8300 [Candidate] entering Candidate state in term 2
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] raft: Votes needed: 1
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] raft: Vote granted from fe893672-44d8-bb7c-0fcb-714f2c329f45 in term 2. Tally: 1
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [INFO] raft: Election won. Tally: 1
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [INFO] raft: Node at 192.168.2.11:8300 [Leader] entering Leader state
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [INFO] consul: cluster leadership acquired
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [INFO] consul: New leader elected: leader01
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [INFO] connect: initialized primary datacenter CA with provider "consul"
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] consul: Skipping self join check for "leader01" since the cluster is too small
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [INFO] consul: member 'leader01' joined, marking health alive
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Skipping remote check "serfHealth" since it is managed automatically
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [INFO] agent: Synced service "http-echo-sidecar-proxy"
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [INFO] agent: Synced service "client"
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [INFO] agent: Synced service "client-sidecar-proxy"
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [INFO] agent: Synced service "http-echo"
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Node info in sync
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Service "http-echo" in sync
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Service "http-echo-sidecar-proxy" in sync
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Service "client" in sync
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Service "client-sidecar-proxy" in sync
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 10:56:16 vagrant consul[1361]:     2019/05/20 10:56:16 [DEBUG] agent: Node info in sync
May 20 10:56:17 vagrant consul[1361]:     2019/05/20 10:56:17 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:56:18 vagrant consul[1361]:     2019/05/20 10:56:18 [DEBUG] tlsutil: OutgoingRPCConfig with version 1
May 20 10:56:18 vagrant consul[1361]:     2019/05/20 10:56:18 [DEBUG] tlsutil: IncomingRPCConfig with version 1
May 20 10:56:18 vagrant consul[1361]:     2019/05/20 10:56:18 [DEBUG] agent: Skipping remote check "serfHealth" since it is managed automatically
May 20 10:56:18 vagrant consul[1361]:     2019/05/20 10:56:18 [DEBUG] agent: Service "http-echo-sidecar-proxy" in sync
May 20 10:56:18 vagrant consul[1361]:     2019/05/20 10:56:18 [DEBUG] agent: Service "client" in sync
May 20 10:56:18 vagrant consul[1361]:     2019/05/20 10:56:18 [DEBUG] agent: Service "client-sidecar-proxy" in sync
May 20 10:56:18 vagrant consul[1361]:     2019/05/20 10:56:18 [DEBUG] agent: Service "http-echo" in sync
May 20 10:56:18 vagrant consul[1361]:     2019/05/20 10:56:18 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 10:56:18 vagrant consul[1361]:     2019/05/20 10:56:18 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 10:56:18 vagrant consul[1361]:     2019/05/20 10:56:18 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 10:56:18 vagrant consul[1361]:     2019/05/20 10:56:18 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 10:56:18 vagrant consul[1361]:     2019/05/20 10:56:18 [DEBUG] agent: Node info in sync
May 20 10:56:24 vagrant consul[1361]:     2019/05/20 10:56:24 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] http: Request PUT /v1/kv/development/consul_version (1.136204ms) from=127.0.0.1:3512
2
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] http: Request PUT /v1/kv/development/vault_version (1.511533ms) from=127.0.0.1:35124
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] http: Request PUT /v1/kv/development/nomad_version (1.360906ms) from=127.0.0.1:35126
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] http: Request PUT /v1/kv/development/terraform_version (1.680743ms) from=127.0.0.1:3
5128
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] http: Request PUT /v1/kv/development/consul_template_version (1.485331ms) from=127.0
.0.1:35130
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] http: Request PUT /v1/kv/development/env_consul_version (2.970339ms) from=127.0.0.1:
35132
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:25 vagrant consul[1361]:     2019/05/20 10:56:25 [DEBUG] http: Request PUT /v1/kv/development/golang_version (1.118015ms) from=127.0.0.1:3513
4
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/inspec_package_url (1.751494ms) from=127.0.0.1:
35136
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/inspec_package (1.178445ms) from=127.0.0.1:3513
8
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/REDIS_MASTER_IP (1.644447ms) from=127.0.0.1:351
40
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/REDIS_MASTER_NAME (988.265µs) from=127.0.0.1:35
142
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/REDIS_HOST_PORT (1.545538ms) from=127.0.0.1:351
44
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/GO_REPOSITORY (2.112135ms) from=127.0.0.1:35146
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/GO_GUEST_PORT (1.615012ms) from=127.0.0.1:35148
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/GO_HOST_PORT (1.393629ms) from=127.0.0.1:35150
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/NGINX_NAME (1.742876ms) from=127.0.0.1:35152
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/NGINX_IP (1.345431ms) from=127.0.0.1:35154
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/NGINX_GUEST_PORT (1.665781ms) from=127.0.0.1:35
156
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/NGINX_HOST_PORT (1.774962ms) from=127.0.0.1:351
58
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/VAULT_NAME (1.667973ms) from=127.0.0.1:35160
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/VAULT_IP (1.225485ms) from=127.0.0.1:35162
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/LEADER_NAME (2.255394ms) from=127.0.0.1:35164
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/LEADER_IP (1.315262ms) from=127.0.0.1:35166
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/NGINX_PUBLIC_IP (2.09267ms) from=127.0.0.1:3516
8
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:26 vagrant consul[1361]:     2019/05/20 10:56:26 [DEBUG] http: Request PUT /v1/kv/development/ (1.304985ms) from=127.0.0.1:35170
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [INFO] agent: Caught signal:  terminated
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [INFO] agent: Graceful shutdown disabled. Exiting
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [INFO] agent: Requesting shutdown
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [DEBUG] agent/proxy: Stopping managed Connect proxy manager
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [INFO] consul: shutting down server
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [WARN] serf: Shutdown without a Leave
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [WARN] serf: Shutdown without a Leave
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [INFO] manager: shutting down
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [INFO] agent: consul server down
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [INFO] agent: shutdown complete
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [INFO] agent: Stopping DNS server 127.0.0.1:8600 (tcp)
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [INFO] agent: Stopping DNS server 127.0.0.1:8600 (udp)
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [INFO] agent: Stopping HTTPS server [::]:8321 (tcp)
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [INFO] agent: Waiting for endpoints to shut down
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [INFO] agent: Endpoints down
May 20 10:56:27 vagrant consul[1361]:     2019/05/20 10:56:27 [INFO] agent: Exit code: 1
May 20 10:56:27 vagrant systemd[1]: consul.service: Main process exited, code=exited, status=1/FAILURE
May 20 10:56:27 vagrant systemd[1]: consul.service: Failed with result 'exit-code'.
May 20 10:56:27 vagrant consul[1620]: BootstrapExpect is set to 1; this is the same as Bootstrap mode.
May 20 10:56:27 vagrant consul[1620]: bootstrap = true: do not enable unless necessary
May 20 10:56:27 vagrant consul[1620]: ==> Starting Consul agent...
May 20 10:56:27 vagrant consul[1620]: ==> Consul agent running!
May 20 10:56:27 vagrant consul[1620]:            Version: 'v1.5.0'
May 20 10:56:27 vagrant consul[1620]:            Node ID: 'fe893672-44d8-bb7c-0fcb-714f2c329f45'
May 20 10:56:27 vagrant consul[1620]:          Node name: 'leader01'
May 20 10:56:27 vagrant consul[1620]:         Datacenter: 'allthingscloud1' (Segment: '<all>')
May 20 10:56:27 vagrant consul[1620]:             Server: true (Bootstrap: true)
May 20 10:56:27 vagrant consul[1620]:        Client Addr: [127.0.0.1] (HTTP: -1, HTTPS: 8321, gRPC: 8502, DNS: 8600)
May 20 10:56:27 vagrant consul[1620]:       Cluster Addr: 192.168.2.11 (LAN: 8301, WAN: 8302)
May 20 10:56:27 vagrant consul[1620]:            Encrypt: Gossip: false, TLS-Outgoing: true, TLS-Incoming: true
May 20 10:56:27 vagrant consul[1620]: ==> Log data will now stream in as it occurs:
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [DEBUG] tlsutil: Update with version 1
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [DEBUG] tlsutil: OutgoingRPCWrapper with version 1
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [DEBUG] tlsutil: IncomingRPCConfig with version 1
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [DEBUG] tlsutil: OutgoingRPCWrapper with version 1
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [INFO] raft: Initial configuration (index=1): [{Suffrage:Voter ID:fe893672-44d8-bb7c-0fcb-71
4f2c329f45 Address:192.168.2.11:8300}]
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [INFO] serf: EventMemberJoin: leader01.allthingscloud1 192.168.2.11
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [INFO] serf: EventMemberJoin: leader01 192.168.2.11
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [INFO] agent: Started DNS server 127.0.0.1:8600 (udp)
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [INFO] raft: Node at 192.168.2.11:8300 [Follower] entering Follower state (Leader: "")
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [WARN] serf: Failed to re-join any previously known node
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [WARN] serf: Failed to re-join any previously known node
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [INFO] consul: Adding LAN server leader01 (Addr: tcp/192.168.2.11:8300) (DC: allthingscloud1
)
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [INFO] consul: Handled member-join event for server "leader01.allthingscloud1" in area "wan"
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [DEBUG] agent/proxy: managed Connect proxy manager started
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [INFO] agent: Started DNS server 127.0.0.1:8600 (tcp)
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [INFO] agent: Started HTTPS server on [::]:8321 (tcp)
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [INFO] agent: started state syncer
May 20 10:56:27 vagrant consul[1620]:     2019/05/20 10:56:27 [INFO] agent: Started gRPC server on 127.0.0.1:8502 (tcp)
May 20 10:56:30 vagrant consul[1620]:     2019/05/20 10:56:30 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:56:34 vagrant consul[1620]:     2019/05/20 10:56:34 [ERR] roots watch error: invalid type for roots response: <nil>
May 20 10:56:34 vagrant consul[1620]:     2019/05/20 10:56:34 [ERR] roots watch error: invalid type for roots response: <nil>
May 20 10:56:34 vagrant consul[1620]:     2019/05/20 10:56:34 [ERR] leaf watch error: invalid type for leaf response: <nil>
May 20 10:56:34 vagrant consul[1620]:     2019/05/20 10:56:34 [ERR] leaf watch error: invalid type for leaf response: <nil>
May 20 10:56:34 vagrant consul[1620]:     2019/05/20 10:56:34 [ERR] upstream:service:http-echo watch error: invalid type for service response: <nil>
May 20 10:56:34 vagrant consul[1620]:     2019/05/20 10:56:34 [ERR] agent: failed to sync remote state: No cluster leader
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [WARN] raft: Heartbeat timeout from "" reached, starting election
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [INFO] raft: Node at 192.168.2.11:8300 [Candidate] entering Candidate state in term 3
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [DEBUG] raft: Votes needed: 1
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [DEBUG] raft: Vote granted from fe893672-44d8-bb7c-0fcb-714f2c329f45 in term 3. Tally: 1
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [INFO] raft: Election won. Tally: 1
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [INFO] raft: Node at 192.168.2.11:8300 [Leader] entering Leader state
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [INFO] consul: cluster leadership acquired
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [INFO] consul: New leader elected: leader01
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [INFO] acl: initializing acls
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [INFO] consul: Created ACL 'global-management' policy
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [INFO] consul: Created ACL anonymous token from configuration
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [INFO] serf: EventMemberUpdate: leader01
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [INFO] serf: EventMemberUpdate: leader01.allthingscloud1
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [DEBUG] consul: Skipping self join check for "leader01" since the cluster is too small
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [DEBUG] consul: Skipping self join check for "leader01" since the cluster is too small
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:35 vagrant consul[1620]: message repeated 10 times: [     2019/05/20 10:56:35 [WARN] consul.intention: Operation on intention prefix 'client'
 denied due to ACLs]
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:35 vagrant consul[1620]: message repeated 10 times: [     2019/05/20 10:56:35 [WARN] consul.intention: Operation on intention prefix 'http-ec
ho' denied due to ACLs]
May 20 10:56:35 vagrant consul[1620]:     2019/05/20 10:56:35 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] consul: dropping check "serfHealth" from result due to ACLs
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] consul: dropping check "service:client-sidecar-proxy:1" from result due to ACLs
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] consul: dropping check "service:client-sidecar-proxy:2" from result due to ACLs
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] consul: dropping check "service:http-echo-sidecar-proxy:1" from result due to ACLs
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] consul: dropping check "service:http-echo-sidecar-proxy:2" from result due to ACLs
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [WARN] agent: Service "http-echo-sidecar-proxy" registration blocked by ACLs
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [WARN] agent: Service "client" registration blocked by ACLs
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [WARN] agent: Service "client-sidecar-proxy" registration blocked by ACLs
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [WARN] agent: Service "http-echo" registration blocked by ACLs
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [INFO] agent: Synced node info
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] agent: Service "client-sidecar-proxy" in sync
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] agent: Service "http-echo" in sync
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] agent: Service "http-echo-sidecar-proxy" in sync
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] agent: Service "client" in sync
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 10:56:36 vagrant consul[1620]:     2019/05/20 10:56:36 [DEBUG] agent: Node info in sync
May 20 10:56:37 vagrant consul[1620]:     2019/05/20 10:56:37 [DEBUG] tlsutil: OutgoingRPCConfig with version 1
May 20 10:56:37 vagrant consul[1620]:     2019/05/20 10:56:37 [DEBUG] tlsutil: IncomingRPCConfig with version 1
May 20 10:56:37 vagrant consul[1620]:     2019/05/20 10:56:37 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:37 vagrant consul[1620]: message repeated 3 times: [     2019/05/20 10:56:37 [WARN] consul.intention: Operation on intention prefix 'http-ech
o' denied due to ACLs]
May 20 10:56:38 vagrant consul[1620]:     2019/05/20 10:56:38 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:38 vagrant consul[1620]:     2019/05/20 10:56:38 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:38 vagrant consul[1620]:     2019/05/20 10:56:38 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:38 vagrant consul[1620]:     2019/05/20 10:56:38 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:38 vagrant consul[1620]:     2019/05/20 10:56:38 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:38 vagrant consul[1620]:     2019/05/20 10:56:38 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:39 vagrant consul[1620]:     2019/05/20 10:56:39 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:39 vagrant consul[1620]: message repeated 3 times: [     2019/05/20 10:56:39 [WARN] consul.intention: Operation on intention prefix 'client'
denied due to ACLs]
May 20 10:56:40 vagrant consul[1620]:     2019/05/20 10:56:40 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:56:42 vagrant consul[1620]:     2019/05/20 10:56:42 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:42 vagrant consul[1620]:     2019/05/20 10:56:42 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:42 vagrant consul[1620]:     2019/05/20 10:56:42 [WARN] acl.bootstrap: failed to remove bootstrap file: remove /usr/local/consul/acl-bootstra
p-reset: no such file or directory
May 20 10:56:42 vagrant consul[1620]:     2019/05/20 10:56:42 [INFO] consul.acl: ACL bootstrap completed
May 20 10:56:42 vagrant consul[1620]:     2019/05/20 10:56:42 [DEBUG] http: Request PUT /v1/acl/bootstrap (2.634546ms) from=127.0.0.1:35180
May 20 10:56:42 vagrant consul[1620]:     2019/05/20 10:56:42 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:42 vagrant consul[1620]:     2019/05/20 10:56:42 [DEBUG] http: Request PUT /v1/acl/policy (1.627324ms) from=127.0.0.1:35182
May 20 10:56:42 vagrant consul[1620]:     2019/05/20 10:56:42 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:42 vagrant consul[1620]: message repeated 3 times: [     2019/05/20 10:56:42 [WARN] consul.intention: Operation on intention prefix 'http-ech
o' denied due to ACLs]
May 20 10:56:42 vagrant consul[1620]:     2019/05/20 10:56:42 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:42 vagrant consul[1620]:     2019/05/20 10:56:42 [DEBUG] http: Request PUT /v1/acl/policy (1.500867ms) from=127.0.0.1:35184
May 20 10:56:42 vagrant consul[1620]:     2019/05/20 10:56:42 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:42 vagrant consul[1620]:     2019/05/20 10:56:42 [DEBUG] http: Request PUT /v1/acl/policy (1.670871ms) from=127.0.0.1:35186
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [DEBUG] http: Request PUT /v1/acl/policy (239.183467ms) from=127.0.0.1:35188
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [DEBUG] http: Request PUT /v1/acl/policy (1.537367ms) from=127.0.0.1:35190
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [DEBUG] http: Request PUT /v1/acl/token (1.601997ms) from=127.0.0.1:35192
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [INFO] agent: Caught signal:  terminated
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [INFO] agent: Graceful shutdown disabled. Exiting
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [INFO] agent: Requesting shutdown
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [DEBUG] agent/proxy: Stopping managed Connect proxy manager
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [INFO] consul: shutting down server
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [WARN] serf: Shutdown without a Leave
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [WARN] serf: Shutdown without a Leave
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [INFO] manager: shutting down
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [WARN] raft: could not get configuration for Stats: raft is already shutdown
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [INFO] agent: consul server down
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [INFO] agent: shutdown complete
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [INFO] agent: Stopping DNS server 127.0.0.1:8600 (tcp)
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [INFO] agent: Stopping DNS server 127.0.0.1:8600 (udp)
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [INFO] agent: Stopping HTTPS server [::]:8321 (tcp)
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [INFO] agent: Waiting for endpoints to shut down
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [INFO] agent: Endpoints down
May 20 10:56:43 vagrant consul[1620]:     2019/05/20 10:56:43 [INFO] agent: Exit code: 1
May 20 10:56:43 vagrant systemd[1]: consul.service: Main process exited, code=exited, status=1/FAILURE
May 20 10:56:43 vagrant systemd[1]: consul.service: Failed with result 'exit-code'.
May 20 10:56:43 vagrant consul[1659]: BootstrapExpect is set to 1; this is the same as Bootstrap mode.
May 20 10:56:43 vagrant consul[1659]: bootstrap = true: do not enable unless necessary
May 20 10:56:43 vagrant consul[1659]: ==> Starting Consul agent...
May 20 10:56:43 vagrant consul[1659]: ==> Consul agent running!
May 20 10:56:43 vagrant consul[1659]:            Version: 'v1.5.0'
May 20 10:56:43 vagrant consul[1659]:            Node ID: 'fe893672-44d8-bb7c-0fcb-714f2c329f45'
May 20 10:56:43 vagrant consul[1659]:          Node name: 'leader01'
May 20 10:56:43 vagrant consul[1659]:         Datacenter: 'allthingscloud1' (Segment: '<all>')
May 20 10:56:43 vagrant consul[1659]:             Server: true (Bootstrap: true)
May 20 10:56:43 vagrant consul[1659]:        Client Addr: [127.0.0.1] (HTTP: -1, HTTPS: 8321, gRPC: 8502, DNS: 8600)
May 20 10:56:43 vagrant consul[1659]:       Cluster Addr: 192.168.2.11 (LAN: 8301, WAN: 8302)
May 20 10:56:43 vagrant consul[1659]:            Encrypt: Gossip: false, TLS-Outgoing: true, TLS-Incoming: true
May 20 10:56:43 vagrant consul[1659]: ==> Log data will now stream in as it occurs:
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [DEBUG] tlsutil: Update with version 1
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [DEBUG] tlsutil: OutgoingRPCWrapper with version 1
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [DEBUG] tlsutil: IncomingRPCConfig with version 1
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [DEBUG] tlsutil: OutgoingRPCWrapper with version 1
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [INFO] raft: Initial configuration (index=1): [{Suffrage:Voter ID:fe893672-44d8-bb7c-0fcb-71
4f2c329f45 Address:192.168.2.11:8300}]
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [INFO] serf: EventMemberJoin: leader01.allthingscloud1 192.168.2.11
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [INFO] serf: EventMemberJoin: leader01 192.168.2.11
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [INFO] agent: Started DNS server 127.0.0.1:8600 (udp)
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [INFO] raft: Node at 192.168.2.11:8300 [Follower] entering Follower state (Leader: "")
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [WARN] serf: Failed to re-join any previously known node
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [WARN] serf: Failed to re-join any previously known node
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [INFO] consul: Adding LAN server leader01 (Addr: tcp/192.168.2.11:8300) (DC: allthingscloud1
)
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [INFO] consul: Handled member-join event for server "leader01.allthingscloud1" in area "wan"
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [DEBUG] agent/proxy: managed Connect proxy manager started
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [INFO] agent: Started DNS server 127.0.0.1:8600 (tcp)
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [INFO] agent: Started HTTPS server on [::]:8321 (tcp)
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [INFO] agent: started state syncer
May 20 10:56:43 vagrant consul[1659]:     2019/05/20 10:56:43 [INFO] agent: Started gRPC server on 127.0.0.1:8502 (tcp)
May 20 10:56:44 vagrant consul[1659]:     2019/05/20 10:56:44 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:56:44 vagrant consul[1659]:     2019/05/20 10:56:44 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [WARN] raft: Heartbeat timeout from "" reached, starting election
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [INFO] raft: Node at 192.168.2.11:8300 [Candidate] entering Candidate state in term 4
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [DEBUG] raft: Votes needed: 1
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [DEBUG] raft: Vote granted from fe893672-44d8-bb7c-0fcb-714f2c329f45 in term 4. Tally: 1
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [INFO] raft: Election won. Tally: 1
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [INFO] raft: Node at 192.168.2.11:8300 [Leader] entering Leader state
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [INFO] consul: cluster leadership acquired
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [INFO] consul: New leader elected: leader01
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [ERR] agent: failed to sync remote state: ACL not found
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [INFO] acl: initializing acls
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [INFO] serf: EventMemberUpdate: leader01
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [INFO] serf: EventMemberUpdate: leader01.allthingscloud1
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [DEBUG] consul: Skipping self join check for "leader01" since the cluster is too small
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [DEBUG] consul: Skipping self join check for "leader01" since the cluster is too small
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [ERR] leaf watch error: invalid type for leaf response: <nil>
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [ERR] leaf watch error: invalid type for leaf response: <nil>
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:50 vagrant consul[1659]: message repeated 15 times: [     2019/05/20 10:56:50 [WARN] consul.intention: Operation on intention prefix 'http-ec
ho' denied due to ACLs]
May 20 10:56:50 vagrant consul[1659]:     2019/05/20 10:56:50 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:50 vagrant consul[1659]: message repeated 11 times: [     2019/05/20 10:56:50 [WARN] consul.intention: Operation on intention prefix 'client'
 denied due to ACLs]
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Skipping remote check "serfHealth" since it is managed automatically
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Service "http-echo-sidecar-proxy" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Service "client" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Service "client-sidecar-proxy" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Service "http-echo" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [INFO] agent: Synced node info
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Service "client" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Service "client-sidecar-proxy" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Service "http-echo" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Service "http-echo-sidecar-proxy" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] agent: Node info in sync
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] tlsutil: OutgoingRPCConfig with version 1
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [DEBUG] tlsutil: IncomingRPCConfig with version 1
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:52 vagrant consul[1659]:     2019/05/20 10:56:52 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:52 vagrant consul[1659]: message repeated 3 times: [     2019/05/20 10:56:52 [WARN] consul.intention: Operation on intention prefix 'http-ech
o' denied due to ACLs]
May 20 10:56:53 vagrant consul[1659]:     2019/05/20 10:56:53 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:53 vagrant consul[1659]:     2019/05/20 10:56:53 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:53 vagrant consul[1659]:     2019/05/20 10:56:53 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:53 vagrant consul[1659]: message repeated 3 times: [     2019/05/20 10:56:53 [WARN] consul.intention: Operation on intention prefix 'client'
denied due to ACLs]
May 20 10:56:54 vagrant consul[1659]:     2019/05/20 10:56:54 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:56:54 vagrant consul[1659]:     2019/05/20 10:56:54 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:54 vagrant consul[1659]:     2019/05/20 10:56:54 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:54 vagrant consul[1659]:     2019/05/20 10:56:54 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:54 vagrant consul[1659]:     2019/05/20 10:56:54 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:56:56 vagrant consul[1659]:     2019/05/20 10:56:56 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:56 vagrant consul[1659]:     2019/05/20 10:56:56 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:58 vagrant consul[1659]:     2019/05/20 10:56:58 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:58 vagrant consul[1659]: message repeated 3 times: [     2019/05/20 10:56:58 [WARN] consul.intention: Operation on intention prefix 'http-ech
o' denied due to ACLs]
May 20 10:56:58 vagrant consul[1659]:     2019/05/20 10:56:58 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:58 vagrant consul[1659]: message repeated 3 times: [     2019/05/20 10:56:58 [WARN] consul.intention: Operation on intention prefix 'client'
denied due to ACLs]
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [DEBUG] http: Request GET /v1/catalog/nodes (403.815µs) from=127.0.0.1:35204
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [DEBUG] http: Request DELETE /v1/kv/development?recurse= (2.141858ms) from=127.0.0.1:35206
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [DEBUG] http: Request PUT /v1/kv/development/consul_version (3.055987ms) from=127.0.0.1:3520
8
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:56:59 vagrant consul[1659]:     2019/05/20 10:56:59 [DEBUG] http: Request PUT /v1/kv/development/vault_version (1.558627ms) from=127.0.0.1:35210
May 20 10:57:00 vagrant consul[1659]:     2019/05/20 10:57:00 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:00 vagrant consul[1659]:     2019/05/20 10:57:00 [DEBUG] http: Request PUT /v1/kv/development/nomad_version (1.742739ms) from=127.0.0.1:35212
May 20 10:57:00 vagrant consul[1659]:     2019/05/20 10:57:00 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:01 vagrant consul[1659]:     2019/05/20 10:57:01 [DEBUG] http: Request PUT /v1/kv/development/terraform_version (4.202144ms) from=127.0.0.1:3
5214
May 20 10:57:01 vagrant consul[1659]:     2019/05/20 10:57:01 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:01 vagrant consul[1659]:     2019/05/20 10:57:01 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:01 vagrant consul[1659]:     2019/05/20 10:57:01 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:01 vagrant consul[1659]:     2019/05/20 10:57:01 [DEBUG] http: Request PUT /v1/kv/development/consul_template_version (1.484117ms) from=127.0
.0.1:35216
May 20 10:57:02 vagrant consul[1659]:     2019/05/20 10:57:02 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:02 vagrant consul[1659]:     2019/05/20 10:57:02 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:02 vagrant consul[1659]:     2019/05/20 10:57:02 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:02 vagrant consul[1659]:     2019/05/20 10:57:02 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:02 vagrant consul[1659]:     2019/05/20 10:57:02 [DEBUG] http: Request PUT /v1/kv/development/env_consul_version (1.622392ms) from=127.0.0.1:
35218
May 20 10:57:02 vagrant consul[1659]:     2019/05/20 10:57:02 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:02 vagrant consul[1659]:     2019/05/20 10:57:02 [DEBUG] http: Request PUT /v1/kv/development/golang_version (1.788574ms) from=127.0.0.1:3522
0
May 20 10:57:03 vagrant consul[1659]:     2019/05/20 10:57:03 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:03 vagrant consul[1659]:     2019/05/20 10:57:03 [DEBUG] http: Request PUT /v1/kv/development/inspec_package_url (2.278722ms) from=127.0.0.1:
35222
May 20 10:57:03 vagrant consul[1659]:     2019/05/20 10:57:03 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:04 vagrant consul[1659]:     2019/05/20 10:57:04 [DEBUG] http: Request PUT /v1/kv/development/inspec_package (239.756808ms) from=127.0.0.1:35
224
May 20 10:57:04 vagrant consul[1659]:     2019/05/20 10:57:04 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:57:04 vagrant consul[1659]:     2019/05/20 10:57:04 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:05 vagrant consul[1659]:     2019/05/20 10:57:05 [DEBUG] http: Request PUT /v1/kv/development/REDIS_MASTER_IP (1.847245ms) from=127.0.0.1:352
28
May 20 10:57:05 vagrant consul[1659]:     2019/05/20 10:57:05 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:05 vagrant consul[1659]:     2019/05/20 10:57:05 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:57:05 vagrant consul[1659]:     2019/05/20 10:57:05 [DEBUG] http: Request PUT /v1/kv/development/REDIS_MASTER_NAME (1.247263ms) from=127.0.0.1:3
5230
May 20 10:57:05 vagrant consul[1659]:     2019/05/20 10:57:05 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:06 vagrant consul[1659]:     2019/05/20 10:57:06 [DEBUG] http: Request PUT /v1/kv/development/REDIS_HOST_PORT (1.823994ms) from=127.0.0.1:352
34
May 20 10:57:06 vagrant consul[1659]:     2019/05/20 10:57:06 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:06 vagrant consul[1659]:     2019/05/20 10:57:06 [DEBUG] http: Request PUT /v1/kv/development/GO_REPOSITORY (1.205006ms) from=127.0.0.1:35236
May 20 10:57:07 vagrant consul[1659]:     2019/05/20 10:57:07 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:07 vagrant consul[1659]:     2019/05/20 10:57:07 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:07 vagrant consul[1659]:     2019/05/20 10:57:07 [DEBUG] http: Request PUT /v1/kv/development/GO_GUEST_PORT (2.150305ms) from=127.0.0.1:35238
May 20 10:57:08 vagrant consul[1659]:     2019/05/20 10:57:08 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:08 vagrant consul[1659]:     2019/05/20 10:57:08 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:08 vagrant consul[1659]: message repeated 3 times: [     2019/05/20 10:57:08 [WARN] consul.intention: Operation on intention prefix 'http-ech
o' denied due to ACLs]
May 20 10:57:08 vagrant consul[1659]:     2019/05/20 10:57:08 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:08 vagrant consul[1659]:     2019/05/20 10:57:08 [DEBUG] http: Request PUT /v1/kv/development/GO_HOST_PORT (1.435233ms) from=127.0.0.1:35240
May 20 10:57:08 vagrant consul[1659]:     2019/05/20 10:57:08 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:09 vagrant consul[1659]:     2019/05/20 10:57:09 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:09 vagrant consul[1659]:     2019/05/20 10:57:09 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:09 vagrant consul[1659]:     2019/05/20 10:57:09 [DEBUG] http: Request PUT /v1/kv/development/NGINX_NAME (2.876987ms) from=127.0.0.1:35242
May 20 10:57:09 vagrant consul[1659]:     2019/05/20 10:57:09 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:09 vagrant consul[1659]: message repeated 3 times: [     2019/05/20 10:57:09 [WARN] consul.intention: Operation on intention prefix 'client'
denied due to ACLs]
May 20 10:57:09 vagrant consul[1659]:     2019/05/20 10:57:09 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:10 vagrant consul[1659]:     2019/05/20 10:57:10 [DEBUG] http: Request PUT /v1/kv/development/NGINX_IP (140.290435ms) from=127.0.0.1:35244
May 20 10:57:10 vagrant consul[1659]:     2019/05/20 10:57:10 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:11 vagrant consul[1659]:     2019/05/20 10:57:11 [DEBUG] http: Request PUT /v1/kv/development/NGINX_GUEST_PORT (1.89209ms) from=127.0.0.1:352
46
May 20 10:57:11 vagrant consul[1659]:     2019/05/20 10:57:11 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:12 vagrant consul[1659]:     2019/05/20 10:57:12 [DEBUG] http: Request PUT /v1/kv/development/NGINX_HOST_PORT (1.401853ms) from=127.0.0.1:352
48
May 20 10:57:12 vagrant consul[1659]:     2019/05/20 10:57:12 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:12 vagrant consul[1659]:     2019/05/20 10:57:12 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:12 vagrant consul[1659]:     2019/05/20 10:57:12 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:13 vagrant consul[1659]:     2019/05/20 10:57:13 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:13 vagrant consul[1659]:     2019/05/20 10:57:13 [DEBUG] http: Request PUT /v1/kv/development/VAULT_NAME (367.245825ms) from=127.0.0.1:35250
May 20 10:57:13 vagrant consul[1659]:     2019/05/20 10:57:13 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:14 vagrant consul[1659]:     2019/05/20 10:57:14 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:14 vagrant consul[1659]:     2019/05/20 10:57:14 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:14 vagrant consul[1659]:     2019/05/20 10:57:14 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:14 vagrant consul[1659]:     2019/05/20 10:57:14 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:14 vagrant consul[1659]:     2019/05/20 10:57:14 [DEBUG] http: Request PUT /v1/kv/development/VAULT_IP (1.525862ms) from=127.0.0.1:35252
May 20 10:57:14 vagrant consul[1659]:     2019/05/20 10:57:14 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:14 vagrant consul[1659]:     2019/05/20 10:57:14 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:14 vagrant consul[1659]:     2019/05/20 10:57:14 [DEBUG] http: Request PUT /v1/kv/development/LEADER_NAME (1.965611ms) from=127.0.0.1:35254
May 20 10:57:15 vagrant consul[1659]:     2019/05/20 10:57:15 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:57:15 vagrant consul[1659]:     2019/05/20 10:57:15 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:15 vagrant consul[1659]:     2019/05/20 10:57:15 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:15 vagrant consul[1659]:     2019/05/20 10:57:15 [DEBUG] http: Request PUT /v1/kv/development/LEADER_IP (2.329741ms) from=127.0.0.1:35258
May 20 10:57:16 vagrant consul[1659]:     2019/05/20 10:57:16 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:16 vagrant consul[1659]:     2019/05/20 10:57:16 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:57:16 vagrant consul[1659]:     2019/05/20 10:57:16 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:16 vagrant consul[1659]:     2019/05/20 10:57:16 [DEBUG] http: Request PUT /v1/kv/development/NGINX_PUBLIC_IP (1.37107ms) from=127.0.0.1:3526
0
May 20 10:57:16 vagrant consul[1659]:     2019/05/20 10:57:16 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:17 vagrant consul[1659]:     2019/05/20 10:57:17 [DEBUG] http: Request PUT /v1/kv/development/ (1.517356ms) from=127.0.0.1:35264
May 20 10:57:17 vagrant consul[1659]:     2019/05/20 10:57:17 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:17 vagrant consul[1659]:     2019/05/20 10:57:17 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:17 vagrant consul[1659]:     2019/05/20 10:57:17 [DEBUG] http: Request GET /v1/kv/development/?recurse= (348.788µs) from=127.0.0.1:35266
May 20 10:57:18 vagrant consul[1659]:     2019/05/20 10:57:18 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:18 vagrant consul[1659]:     2019/05/20 10:57:18 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:57:18 vagrant consul[1659]:     2019/05/20 10:57:18 [DEBUG] http: Request GET /v1/agent/members?segment=_all (274.708µs) from=127.0.0.1:35268
May 20 10:57:21 vagrant consul[1659]:     2019/05/20 10:57:21 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:25 vagrant consul[1659]:     2019/05/20 10:57:25 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:57:27 vagrant consul[1659]:     2019/05/20 10:57:27 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:27 vagrant consul[1659]:     2019/05/20 10:57:27 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:57:27 vagrant consul[1659]:     2019/05/20 10:57:27 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:31 vagrant consul[1659]:     2019/05/20 10:57:31 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:32 vagrant consul[1659]:     2019/05/20 10:57:32 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:33 vagrant consul[1659]:     2019/05/20 10:57:33 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:33 vagrant consul[1659]: message repeated 3 times: [     2019/05/20 10:57:33 [WARN] consul.intention: Operation on intention prefix 'client'
denied due to ACLs]
May 20 10:57:36 vagrant consul[1659]:     2019/05/20 10:57:36 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:57:36 vagrant consul[1659]:     2019/05/20 10:57:36 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:37 vagrant consul[1659]:     2019/05/20 10:57:37 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:57:38 vagrant consul[1659]:     2019/05/20 10:57:38 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:38 vagrant consul[1659]: message repeated 3 times: [     2019/05/20 10:57:38 [WARN] consul.intention: Operation on intention prefix 'client'
denied due to ACLs]
May 20 10:57:38 vagrant consul[1659]:     2019/05/20 10:57:38 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:38 vagrant consul[1659]: message repeated 3 times: [     2019/05/20 10:57:38 [WARN] consul.intention: Operation on intention prefix 'http-ech
o' denied due to ACLs]
May 20 10:57:39 vagrant consul[1659]:     2019/05/20 10:57:39 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:41 vagrant consul[1659]:     2019/05/20 10:57:41 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:41 vagrant consul[1659]:     2019/05/20 10:57:41 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:43 vagrant consul[1659]:     2019/05/20 10:57:43 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:45 vagrant consul[1659]:     2019/05/20 10:57:45 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:46 vagrant consul[1659]:     2019/05/20 10:57:46 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:46 vagrant consul[1659]:     2019/05/20 10:57:46 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:57:48 vagrant consul[1659]:     2019/05/20 10:57:48 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:48 vagrant consul[1659]:     2019/05/20 10:57:48 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:48 vagrant consul[1659]:     2019/05/20 10:57:48 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:57:49 vagrant consul[1659]:     2019/05/20 10:57:49 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:57:51 vagrant consul[1659]:     2019/05/20 10:57:51 [DEBUG] consul: Skipping self join check for "leader01" since the cluster is too small
May 20 10:57:57 vagrant consul[1659]:     2019/05/20 10:57:57 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:57:57 vagrant consul[1659]:     2019/05/20 10:57:57 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:57:59 vagrant consul[1659]:     2019/05/20 10:57:59 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:58:00 vagrant consul[1659]:     2019/05/20 10:58:00 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:58:01 vagrant consul[1659]:     2019/05/20 10:58:01 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:58:07 vagrant consul[1659]:     2019/05/20 10:58:07 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:58:09 vagrant consul[1659]:     2019/05/20 10:58:09 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:58:10 vagrant consul[1659]:     2019/05/20 10:58:10 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:58:10 vagrant consul[1659]:     2019/05/20 10:58:10 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:58:10 vagrant consul[1659]:     2019/05/20 10:58:10 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:58:11 vagrant consul[1659]:     2019/05/20 10:58:11 [DEBUG] memberlist: Stream connection from=192.168.2.101:56912
May 20 10:58:11 vagrant consul[1659]:     2019/05/20 10:58:11 [INFO] serf: EventMemberJoin: app01 192.168.2.101
May 20 10:58:11 vagrant consul[1659]:     2019/05/20 10:58:11 [INFO] consul: member 'app01' joined, marking health alive
May 20 10:58:11 vagrant consul[1659]:     2019/05/20 10:58:11 [DEBUG] tlsutil: IncomingRPCConfig with version 1
May 20 10:58:11 vagrant consul[1659]:     2019/05/20 10:58:11 [DEBUG] serf: messageJoinType: app01
May 20 10:58:11 vagrant consul[1659]:     2019/05/20 10:58:11 [DEBUG] serf: messageJoinType: app01
May 20 10:58:12 vagrant consul[1659]:     2019/05/20 10:58:12 [DEBUG] serf: messageJoinType: app01
May 20 10:58:12 vagrant consul[1659]:     2019/05/20 10:58:12 [DEBUG] serf: messageJoinType: app01
May 20 10:58:12 vagrant consul[1659]:     2019/05/20 10:58:12 [DEBUG] consul: dropping check "serfHealth" from result due to ACLs
May 20 10:58:12 vagrant consul[1659]:     2019/05/20 10:58:12 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:58:14 vagrant consul[1659]:     2019/05/20 10:58:14 [DEBUG] consul: dropping check "serfHealth" from result due to ACLs
May 20 10:58:18 vagrant consul[1659]:     2019/05/20 10:58:18 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:58:18 vagrant consul[1659]:     2019/05/20 10:58:18 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:58:18 vagrant consul[1659]:     2019/05/20 10:58:18 [DEBUG] memberlist: Initiating push/pull sync with: 192.168.2.101:8301
May 20 10:58:20 vagrant consul[1659]:     2019/05/20 10:58:20 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:58:20 vagrant consul[1659]:     2019/05/20 10:58:20 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:58:22 vagrant consul[1659]:     2019/05/20 10:58:22 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:58:22 vagrant consul[1659]:     2019/05/20 10:58:22 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:58:24 vagrant consul[1659]:     2019/05/20 10:58:24 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:58:27 vagrant consul[1659]:     2019/05/20 10:58:27 [DEBUG] agent: Skipping remote check "serfHealth" since it is managed automatically
May 20 10:58:27 vagrant consul[1659]:     2019/05/20 10:58:27 [DEBUG] agent: Service "http-echo" in sync
May 20 10:58:27 vagrant consul[1659]:     2019/05/20 10:58:27 [DEBUG] agent: Service "http-echo-sidecar-proxy" in sync
May 20 10:58:27 vagrant consul[1659]:     2019/05/20 10:58:27 [DEBUG] agent: Service "client" in sync
May 20 10:58:27 vagrant consul[1659]:     2019/05/20 10:58:27 [DEBUG] agent: Service "client-sidecar-proxy" in sync
May 20 10:58:27 vagrant consul[1659]:     2019/05/20 10:58:27 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 10:58:27 vagrant consul[1659]:     2019/05/20 10:58:27 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 10:58:27 vagrant consul[1659]:     2019/05/20 10:58:27 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 10:58:27 vagrant consul[1659]:     2019/05/20 10:58:27 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 10:58:27 vagrant consul[1659]:     2019/05/20 10:58:27 [DEBUG] agent: Node info in sync
May 20 10:58:28 vagrant consul[1659]:     2019/05/20 10:58:28 [DEBUG] serf: messageLeaveType: app01
May 20 10:58:28 vagrant consul[1659]:     2019/05/20 10:58:28 [DEBUG] serf: messageLeaveType: app01
May 20 10:58:28 vagrant consul[1659]:     2019/05/20 10:58:28 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:58:29 vagrant consul[1659]:     2019/05/20 10:58:29 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:58:29 vagrant consul[1659]: message repeated 3 times: [     2019/05/20 10:58:29 [WARN] consul.intention: Operation on intention prefix 'client'
denied due to ACLs]
May 20 10:58:29 vagrant consul[1659]:     2019/05/20 10:58:29 [DEBUG] serf: messageLeaveType: app01
May 20 10:58:29 vagrant consul[1659]:     2019/05/20 10:58:29 [DEBUG] serf: messageLeaveType: app01
May 20 10:58:29 vagrant consul[1659]:     2019/05/20 10:58:29 [INFO] serf: EventMemberLeave: app01 192.168.2.101
May 20 10:58:29 vagrant consul[1659]:     2019/05/20 10:58:29 [INFO] consul: member 'app01' left, deregistering
May 20 10:58:31 vagrant consul[1659]:     2019/05/20 10:58:31 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:58:32 vagrant consul[1659]:     2019/05/20 10:58:32 [WARN] consul.intention: Operation on intention prefix 'http-echo' denied due to ACLs
May 20 10:58:32 vagrant consul[1659]: message repeated 4 times: [     2019/05/20 10:58:32 [WARN] consul.intention: Operation on intention prefix 'http-ech
o' denied due to ACLs]
May 20 10:58:32 vagrant consul[1659]:     2019/05/20 10:58:32 [WARN] consul.intention: Operation on intention prefix 'client' denied due to ACLs
May 20 10:58:32 vagrant consul[1659]:     2019/05/20 10:58:32 [DEBUG] memberlist: Stream connection from=192.168.2.101:56920
May 20 10:58:32 vagrant consul[1659]:     2019/05/20 10:58:32 [DEBUG] tlsutil: IncomingRPCConfig with version 1
May 20 10:58:32 vagrant consul[1659]:     2019/05/20 10:58:32 [INFO] serf: EventMemberJoin: app01 192.168.2.101
```

## app01 logs

``` bash
vagrant@app01:~$ sudo grep -E 'consul|envoy' /var/log/syslog | more
May 20 10:58:11 vagrant consul[1367]: ==> Starting Consul agent...
May 20 10:58:11 vagrant consul[1367]: ==> Joining cluster...
May 20 10:58:11 vagrant consul[1367]:     Join completed. Synced with 1 initial agents
May 20 10:58:11 vagrant consul[1367]: ==> Consul agent running!
May 20 10:58:11 vagrant consul[1367]:            Version: 'v1.5.0'
May 20 10:58:11 vagrant consul[1367]:            Node ID: 'efb804c7-5b65-ba5c-2bac-c3911e42d08c'
May 20 10:58:11 vagrant consul[1367]:          Node name: 'app01'
May 20 10:58:11 vagrant consul[1367]:         Datacenter: 'allthingscloud1' (Segment: '')
May 20 10:58:11 vagrant consul[1367]:             Server: false (Bootstrap: false)
May 20 10:58:11 vagrant consul[1367]:        Client Addr: [127.0.0.1] (HTTP: -1, HTTPS: 8321, gRPC: -1, DNS: 8600)
May 20 10:58:11 vagrant consul[1367]:       Cluster Addr: 192.168.2.101 (LAN: 8301, WAN: 8302)
May 20 10:58:11 vagrant consul[1367]:            Encrypt: Gossip: false, TLS-Outgoing: true, TLS-Incoming: true
May 20 10:58:11 vagrant consul[1367]: ==> Log data will now stream in as it occurs:
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [DEBUG] agent: Using random ID "efb804c7-5b65-ba5c-2bac-c3911e42d08c" as node ID
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [DEBUG] tlsutil: Update with version 1
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [DEBUG] tlsutil: OutgoingRPCWrapper with version 1
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [INFO] serf: EventMemberJoin: app01 192.168.2.101
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [INFO] agent: Started DNS server 127.0.0.1:8600 (udp)
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [DEBUG] agent/proxy: managed Connect proxy manager started
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [INFO] agent: Started DNS server 127.0.0.1:8600 (tcp)
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [INFO] agent: Started HTTPS server on [::]:8321 (tcp)
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [INFO] agent: (LAN) joining: [192.168.2.11]
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [DEBUG] memberlist: Initiating push/pull sync with: 192.168.2.11:8301
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [INFO] serf: EventMemberJoin: leader01 192.168.2.11
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [INFO] agent: (LAN) joined: 1 Err: <nil>
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [DEBUG] agent: systemd notify failed: No socket
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [INFO] agent: started state syncer
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [INFO] consul: adding server leader01 (Addr: tcp/192.168.2.11:8300) (DC: allthingscloud1)
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [DEBUG] tlsutil: OutgoingRPCConfig with version 1
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [DEBUG] serf: messageUserEventType: consul:new-leader
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [DEBUG] serf: messageUserEventType: consul:new-leader
May 20 10:58:11 vagrant consul[1367]:     2019/05/20 10:58:11 [DEBUG] serf: messageJoinType: app01
May 20 10:58:12 vagrant consul[1367]:     2019/05/20 10:58:12 [DEBUG] serf: messageUserEventType: consul:new-leader
May 20 10:58:12 vagrant consul[1367]:     2019/05/20 10:58:12 [DEBUG] serf: messageJoinType: app01
May 20 10:58:12 vagrant consul[1367]:     2019/05/20 10:58:12 [DEBUG] serf: messageUserEventType: consul:new-leader
May 20 10:58:12 vagrant consul[1367]:     2019/05/20 10:58:12 [DEBUG] serf: messageJoinType: app01
May 20 10:58:12 vagrant consul[1367]:     2019/05/20 10:58:12 [DEBUG] serf: messageJoinType: app01
May 20 10:58:12 vagrant consul[1367]:     2019/05/20 10:58:12 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 10:58:12 vagrant consul[1367]:     2019/05/20 10:58:12 [WARN] agent: Node info update blocked by ACLs
May 20 10:58:12 vagrant consul[1367]:     2019/05/20 10:58:12 [DEBUG] agent: Node info in sync
May 20 10:58:15 vagrant consul[1367]:     2019/05/20 10:58:15 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 10:58:15 vagrant consul[1367]:     2019/05/20 10:58:15 [WARN] agent: Node info update blocked by ACLs
May 20 10:58:18 vagrant consul[1367]:     2019/05/20 10:58:18 [DEBUG] memberlist: Stream connection from=192.168.2.11:33556
May 20 10:58:26 vagrant consul[1367]:     2019/05/20 10:58:26 [ERR] consul: "Coordinate.Update" RPC failed to server 192.168.2.11:8300: rpc error making c
all: Permission denied
May 20 10:58:26 vagrant consul[1367]:     2019/05/20 10:58:26 [WARN] agent: Coordinate update blocked by ACLs
May 20 10:58:28 vagrant consul[1367]:     2019/05/20 10:58:28 [INFO] agent: Caught signal:  terminated
May 20 10:58:28 vagrant consul[1367]:     2019/05/20 10:58:28 [INFO] agent: Gracefully shutting down agent...
May 20 10:58:28 vagrant consul[1367]:     2019/05/20 10:58:28 [INFO] consul: client starting leave
May 20 10:58:28 vagrant consul[1367]:     2019/05/20 10:58:28 [DEBUG] serf: messageLeaveType: app01
May 20 10:58:28 vagrant consul[1367]:     2019/05/20 10:58:28 [INFO] serf: EventMemberLeave: app01 192.168.2.101
May 20 10:58:29 vagrant consul[1367]:     2019/05/20 10:58:29 [DEBUG] serf: messageLeaveType: app01
May 20 10:58:29 vagrant consul[1367]: message repeated 2 times: [     2019/05/20 10:58:29 [DEBUG] serf: messageLeaveType: app01]
May 20 10:58:32 vagrant consul[1367]:     2019/05/20 10:58:32 [INFO] agent: Graceful exit completed
May 20 10:58:32 vagrant consul[1367]:     2019/05/20 10:58:32 [INFO] agent: Requesting shutdown
May 20 10:58:32 vagrant consul[1367]:     2019/05/20 10:58:32 [DEBUG] agent/proxy: Stopping managed Connect proxy manager
May 20 10:58:32 vagrant consul[1367]:     2019/05/20 10:58:32 [INFO] consul: shutting down client
May 20 10:58:32 vagrant consul[1367]:     2019/05/20 10:58:32 [INFO] manager: shutting down
May 20 10:58:32 vagrant consul[1367]:     2019/05/20 10:58:32 [INFO] agent: consul client down
May 20 10:58:32 vagrant consul[1367]:     2019/05/20 10:58:32 [INFO] agent: shutdown complete
May 20 10:58:32 vagrant consul[1367]:     2019/05/20 10:58:32 [INFO] agent: Stopping DNS server 127.0.0.1:8600 (tcp)
May 20 10:58:32 vagrant consul[1367]:     2019/05/20 10:58:32 [INFO] agent: Stopping DNS server 127.0.0.1:8600 (udp)
May 20 10:58:32 vagrant consul[1367]:     2019/05/20 10:58:32 [INFO] agent: Stopping HTTPS server [::]:8321 (tcp)
May 20 10:58:32 vagrant consul[1367]:     2019/05/20 10:58:32 [INFO] agent: Waiting for endpoints to shut down
May 20 10:58:32 vagrant consul[1367]:     2019/05/20 10:58:32 [INFO] agent: Endpoints down
May 20 10:58:32 vagrant consul[1367]:     2019/05/20 10:58:32 [INFO] agent: Exit code: 0
May 20 10:58:32 vagrant consul[1432]: ==> Starting Consul agent...
May 20 10:58:32 vagrant consul[1432]: ==> Joining cluster...
May 20 10:58:32 vagrant consul[1432]:     Join completed. Synced with 1 initial agents
May 20 10:58:32 vagrant consul[1432]: ==> Consul agent running!
May 20 10:58:32 vagrant consul[1432]:            Version: 'v1.5.0'
May 20 10:58:32 vagrant consul[1432]:            Node ID: 'efb804c7-5b65-ba5c-2bac-c3911e42d08c'
May 20 10:58:32 vagrant consul[1432]:          Node name: 'app01'
May 20 10:58:32 vagrant consul[1432]:         Datacenter: 'allthingscloud1' (Segment: '')
May 20 10:58:32 vagrant consul[1432]:             Server: false (Bootstrap: false)
May 20 10:58:32 vagrant consul[1432]:        Client Addr: [127.0.0.1] (HTTP: -1, HTTPS: 8321, gRPC: -1, DNS: 8600)
May 20 10:58:32 vagrant consul[1432]:       Cluster Addr: 192.168.2.101 (LAN: 8301, WAN: 8302)
May 20 10:58:32 vagrant consul[1432]:            Encrypt: Gossip: false, TLS-Outgoing: true, TLS-Incoming: true
May 20 10:58:32 vagrant consul[1432]: ==> Log data will now stream in as it occurs:
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [DEBUG] tlsutil: Update with version 1
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [DEBUG] tlsutil: OutgoingRPCWrapper with version 1
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [INFO] serf: EventMemberJoin: app01 192.168.2.101
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [INFO] agent: Started DNS server 127.0.0.1:8600 (udp)
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [DEBUG] agent/proxy: managed Connect proxy manager started
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [INFO] agent: Started DNS server 127.0.0.1:8600 (tcp)
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [INFO] agent: Started HTTPS server on [::]:8321 (tcp)
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [INFO] agent: (LAN) joining: [192.168.2.11]
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [WARN] manager: No servers available
May 20 10:58:32 vagrant consul[1432]: message repeated 55 times: [     2019/05/20 10:58:32 [WARN] manager: No servers available]
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [ERR] roots watch error: invalid type for roots response: <nil>
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [WARN] manager: No servers available
May 20 10:58:32 vagrant consul[1432]: message repeated 3 times: [     2019/05/20 10:58:32 [WARN] manager: No servers available]
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [ERR] leaf watch error: invalid type for leaf response: <nil>
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [WARN] manager: No servers available
May 20 10:58:32 vagrant consul[1432]: message repeated 7 times: [     2019/05/20 10:58:32 [WARN] manager: No servers available]
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [ERR] roots watch error: invalid type for roots response: <nil>
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [ERR] upstream:service:http-echo watch error: invalid type for service response: <nil>
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [WARN] manager: No servers available
May 20 10:58:32 vagrant consul[1432]: message repeated 3 times: [     2019/05/20 10:58:32 [WARN] manager: No servers available]
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [ERR] leaf watch error: invalid type for leaf response: <nil>
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [WARN] manager: No servers available
May 20 10:58:32 vagrant consul[1432]: message repeated 39 times: [     2019/05/20 10:58:32 [WARN] manager: No servers available]
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [DEBUG] memberlist: Initiating push/pull sync with: 192.168.2.11:8301
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [WARN] memberlist: Refuting a suspect message (from: app01)
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [INFO] serf: EventMemberJoin: leader01 192.168.2.11
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [DEBUG] serf: Refuting an older leave intent
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [INFO] agent: (LAN) joined: 1 Err: <nil>
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [DEBUG] agent: systemd notify failed: No socket
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [INFO] agent: started state syncer
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [INFO] consul: adding server leader01 (Addr: tcp/192.168.2.11:8300) (DC: allthingscloud1)
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [DEBUG] tlsutil: OutgoingRPCConfig with version 1
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [DEBUG] acl: transition out of legacy ACL mode
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [INFO] serf: EventMemberUpdate: app01
May 20 10:58:32 vagrant consul[1432]:     2019/05/20 10:58:32 [DEBUG] serf: messageJoinType: app01
May 20 10:58:33 vagrant consul[1432]:     2019/05/20 10:58:33 [DEBUG] serf: messageJoinType: app01
May 20 10:58:33 vagrant consul[1432]: message repeated 2 times: [     2019/05/20 10:58:33 [DEBUG] serf: messageJoinType: app01]
May 20 10:58:33 vagrant consul[1432]:     2019/05/20 10:58:33 [DEBUG] agent: Skipping remote check "serfHealth" since it is managed automatically
May 20 10:58:34 vagrant consul[1432]:     2019/05/20 10:58:34 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 10:58:34 vagrant consul[1432]:     2019/05/20 10:58:34 [WARN] agent: Service "http-echo-sidecar-proxy" registration blocked by ACLs
May 20 10:58:34 vagrant consul[1432]:     2019/05/20 10:58:34 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 10:58:34 vagrant consul[1432]:     2019/05/20 10:58:34 [WARN] agent: Service "client" registration blocked by ACLs
May 20 10:58:34 vagrant consul[1432]:     2019/05/20 10:58:34 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 10:58:34 vagrant consul[1432]:     2019/05/20 10:58:34 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 10:58:34 vagrant consul[1432]:     2019/05/20 10:58:34 [WARN] agent: Service "client-sidecar-proxy" registration blocked by ACLs
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [WARN] agent: Service "http-echo" registration blocked by ACLs
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [INFO] agent: Synced node info
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [DEBUG] agent: Service "client-sidecar-proxy" in sync
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [DEBUG] agent: Service "http-echo" in sync
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [DEBUG] agent: Service "http-echo-sidecar-proxy" in sync
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [DEBUG] agent: Service "client" in sync
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [DEBUG] agent: Node info in sync
May 20 10:58:35 vagrant consul[1432]:     2019/05/20 10:58:35 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:36 vagrant consul[1432]:     2019/05/20 10:58:36 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 10:58:36 vagrant consul[1432]:     2019/05/20 10:58:36 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:36 vagrant consul[1432]:     2019/05/20 10:58:36 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 10:58:36 vagrant consul[1432]:     2019/05/20 10:58:36 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:36 vagrant consul[1432]:     2019/05/20 10:58:36 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:36 vagrant consul[1432]:     2019/05/20 10:58:36 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 10:58:37 vagrant consul[1432]:     2019/05/20 10:58:37 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 10:58:37 vagrant consul[1432]:     2019/05/20 10:58:37 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 10:58:38 vagrant consul[1432]:     2019/05/20 10:58:38 [DEBUG] agent: Skipping remote check "serfHealth" since it is managed automatically
May 20 10:58:38 vagrant consul[1432]:     2019/05/20 10:58:38 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 10:58:38 vagrant consul[1432]:     2019/05/20 10:58:38 [WARN] agent: Service "http-echo" registration blocked by ACLs
May 20 10:58:38 vagrant consul[1432]:     2019/05/20 10:58:38 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 10:58:38 vagrant consul[1432]:     2019/05/20 10:58:38 [WARN] agent: Service "http-echo-sidecar-proxy" registration blocked by ACLs
May 20 10:58:38 vagrant consul[1432]:     2019/05/20 10:58:38 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 10:58:38 vagrant consul[1432]:     2019/05/20 10:58:38 [WARN] agent: Service "client" registration blocked by ACLs
May 20 10:58:38 vagrant consul[1432]:     2019/05/20 10:58:38 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 10:58:39 vagrant consul[1432]:     2019/05/20 10:58:39 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 10:58:39 vagrant consul[1432]:     2019/05/20 10:58:39 [WARN] agent: Service "client-sidecar-proxy" registration blocked by ACLs
May 20 10:58:39 vagrant consul[1432]:     2019/05/20 10:58:39 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 10:58:39 vagrant consul[1432]:     2019/05/20 10:58:39 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 10:58:39 vagrant consul[1432]:     2019/05/20 10:58:39 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 10:58:39 vagrant consul[1432]:     2019/05/20 10:58:39 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 10:58:39 vagrant consul[1432]:     2019/05/20 10:58:39 [DEBUG] agent: Node info in sync
May 20 10:58:39 vagrant consul[1432]:     2019/05/20 10:58:39 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:39 vagrant consul[1432]:     2019/05/20 10:58:39 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:40 vagrant consul[1432]:     2019/05/20 10:58:40 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:40 vagrant consul[1432]:     2019/05/20 10:58:40 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 10:58:40 vagrant consul[1432]:     2019/05/20 10:58:40 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:40 vagrant consul[1432]:     2019/05/20 10:58:40 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:41 vagrant consul[1432]:     2019/05/20 10:58:41 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 10:58:41 vagrant consul[1432]:     2019/05/20 10:58:41 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:41 vagrant consul[1432]:     2019/05/20 10:58:41 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 10:58:41 vagrant consul[1432]: message repeated 3 times: [     2019/05/20 10:58:41 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11
:8300: rpc error making call: Permission denied]
May 20 10:58:42 vagrant consul[1432]:     2019/05/20 10:58:42 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 10:58:42 vagrant consul[1432]: message repeated 2 times: [     2019/05/20 10:58:42 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11
:8300: rpc error making call: Permission denied]
May 20 10:58:43 vagrant consul[1432]:     2019/05/20 10:58:43 [DEBUG] memberlist: Failed ping: leader01 (timeout reached)
May 20 10:58:44 vagrant consul[1432]:     2019/05/20 10:58:44 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 10:58:44 vagrant consul[1432]:     2019/05/20 10:58:44 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 10:58:44 vagrant consul[1432]:     2019/05/20 10:58:44 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
```

## client01 logs

``` bash
vagrant@client01:~$ sudo grep -E 'consul|envoy' /var/log/syslog | more
May 20 10:59:43 vagrant consul[1358]: ==> Starting Consul agent...
May 20 10:59:43 vagrant consul[1358]: ==> Joining cluster...
May 20 10:59:43 vagrant consul[1358]:     Join completed. Synced with 1 initial agents
May 20 10:59:43 vagrant consul[1358]: ==> Consul agent running!
May 20 10:59:43 vagrant consul[1358]:            Version: 'v1.5.0'
May 20 10:59:43 vagrant consul[1358]:            Node ID: '01868353-71dd-b2a0-ccc7-092d1ca9fee5'
May 20 10:59:43 vagrant consul[1358]:          Node name: 'client01'
May 20 10:59:43 vagrant consul[1358]:         Datacenter: 'allthingscloud1' (Segment: '')
May 20 10:59:43 vagrant consul[1358]:             Server: false (Bootstrap: false)
May 20 10:59:43 vagrant consul[1358]:        Client Addr: [127.0.0.1] (HTTP: -1, HTTPS: 8321, gRPC: -1, DNS: 8600)
May 20 10:59:43 vagrant consul[1358]:       Cluster Addr: 192.168.2.201 (LAN: 8301, WAN: 8302)
May 20 10:59:43 vagrant consul[1358]:            Encrypt: Gossip: false, TLS-Outgoing: true, TLS-Incoming: true
May 20 10:59:43 vagrant consul[1358]: ==> Log data will now stream in as it occurs:
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [DEBUG] agent: Using random ID "01868353-71dd-b2a0-ccc7-092d1ca9fee5" as node ID
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [DEBUG] tlsutil: Update with version 1
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [DEBUG] tlsutil: OutgoingRPCWrapper with version 1
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [INFO] serf: EventMemberJoin: client01 192.168.2.201
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [INFO] agent: Started DNS server 127.0.0.1:8600 (udp)
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [DEBUG] agent/proxy: managed Connect proxy manager started
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [INFO] agent: Started DNS server 127.0.0.1:8600 (tcp)
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [INFO] agent: Started HTTPS server on [::]:8321 (tcp)
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [INFO] agent: (LAN) joining: [192.168.2.11]
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [DEBUG] memberlist: Initiating push/pull sync with: 192.168.2.11:8301
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [INFO] serf: EventMemberJoin: leader01 192.168.2.11
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [INFO] serf: EventMemberJoin: app01 192.168.2.101
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [INFO] agent: (LAN) joined: 1 Err: <nil>
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [DEBUG] agent: systemd notify failed: No socket
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [INFO] agent: started state syncer
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [INFO] consul: adding server leader01 (Addr: tcp/192.168.2.11:8300) (DC: allthingscloud1)
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [DEBUG] tlsutil: OutgoingRPCConfig with version 1
May 20 10:59:43 vagrant consul[1358]:     2019/05/20 10:59:43 [DEBUG] serf: messageJoinType: client01
May 20 10:59:43 vagrant consul[1358]: message repeated 2 times: [     2019/05/20 10:59:43 [DEBUG] serf: messageJoinType: client01]
May 20 10:59:44 vagrant consul[1358]:     2019/05/20 10:59:44 [DEBUG] serf: messageJoinType: client01
May 20 10:59:44 vagrant consul[1358]:     2019/05/20 10:59:44 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 10:59:44 vagrant consul[1358]:     2019/05/20 10:59:44 [WARN] agent: Node info update blocked by ACLs
May 20 10:59:46 vagrant consul[1358]:     2019/05/20 10:59:46 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 10:59:46 vagrant consul[1358]:     2019/05/20 10:59:46 [WARN] agent: Node info update blocked by ACLs
May 20 10:59:46 vagrant consul[1358]:     2019/05/20 10:59:46 [DEBUG] agent: Node info in sync
May 20 10:59:49 vagrant consul[1358]:     2019/05/20 10:59:49 [DEBUG] memberlist: Failed ping: leader01 (timeout reached)
May 20 10:59:50 vagrant consul[1358]:     2019/05/20 10:59:50 [DEBUG] memberlist: Stream connection from=192.168.2.11:60918
May 20 11:00:00 vagrant consul[1358]:     2019/05/20 11:00:00 [INFO] agent: Caught signal:  terminated
May 20 11:00:00 vagrant consul[1358]:     2019/05/20 11:00:00 [INFO] agent: Gracefully shutting down agent...
May 20 11:00:00 vagrant consul[1358]:     2019/05/20 11:00:00 [INFO] consul: client starting leave
May 20 11:00:00 vagrant consul[1358]:     2019/05/20 11:00:00 [DEBUG] serf: messageLeaveType: client01
May 20 11:00:00 vagrant consul[1358]:     2019/05/20 11:00:00 [INFO] serf: EventMemberLeave: client01 192.168.2.201
May 20 11:00:00 vagrant consul[1358]:     2019/05/20 11:00:00 [DEBUG] serf: messageLeaveType: client01
May 20 11:00:01 vagrant consul[1358]:     2019/05/20 11:00:01 [DEBUG] serf: messageLeaveType: client01
May 20 11:00:01 vagrant consul[1358]: message repeated 2 times: [     2019/05/20 11:00:01 [DEBUG] serf: messageLeaveType: client01]
May 20 11:00:04 vagrant consul[1358]:     2019/05/20 11:00:04 [INFO] agent: Graceful exit completed
May 20 11:00:04 vagrant consul[1358]:     2019/05/20 11:00:04 [INFO] agent: Requesting shutdown
May 20 11:00:04 vagrant consul[1358]:     2019/05/20 11:00:04 [DEBUG] agent/proxy: Stopping managed Connect proxy manager
May 20 11:00:04 vagrant consul[1358]:     2019/05/20 11:00:04 [INFO] consul: shutting down client
May 20 11:00:04 vagrant consul[1358]:     2019/05/20 11:00:04 [INFO] manager: shutting down
May 20 11:00:04 vagrant consul[1358]:     2019/05/20 11:00:04 [INFO] agent: consul client down
May 20 11:00:04 vagrant consul[1358]:     2019/05/20 11:00:04 [INFO] agent: shutdown complete
May 20 11:00:04 vagrant consul[1358]:     2019/05/20 11:00:04 [INFO] agent: Stopping DNS server 127.0.0.1:8600 (tcp)
May 20 11:00:04 vagrant consul[1358]:     2019/05/20 11:00:04 [INFO] agent: Stopping DNS server 127.0.0.1:8600 (udp)
May 20 11:00:04 vagrant consul[1358]:     2019/05/20 11:00:04 [INFO] agent: Stopping HTTPS server [::]:8321 (tcp)
May 20 11:00:04 vagrant consul[1358]:     2019/05/20 11:00:04 [INFO] agent: Waiting for endpoints to shut down
May 20 11:00:04 vagrant consul[1358]:     2019/05/20 11:00:04 [INFO] agent: Endpoints down
May 20 11:00:04 vagrant consul[1358]:     2019/05/20 11:00:04 [INFO] agent: Exit code: 0
May 20 11:00:04 vagrant consul[1421]: ==> Starting Consul agent...
May 20 11:00:04 vagrant consul[1421]: ==> Joining cluster...
May 20 11:00:04 vagrant consul[1421]:     Join completed. Synced with 1 initial agents
May 20 11:00:04 vagrant consul[1421]: ==> Consul agent running!
May 20 11:00:04 vagrant consul[1421]:            Version: 'v1.5.0'
May 20 11:00:04 vagrant consul[1421]:            Node ID: '01868353-71dd-b2a0-ccc7-092d1ca9fee5'
May 20 11:00:04 vagrant consul[1421]:          Node name: 'client01'
May 20 11:00:04 vagrant consul[1421]:         Datacenter: 'allthingscloud1' (Segment: '')
May 20 11:00:04 vagrant consul[1421]:             Server: false (Bootstrap: false)
May 20 11:00:04 vagrant consul[1421]:        Client Addr: [127.0.0.1] (HTTP: -1, HTTPS: 8321, gRPC: -1, DNS: 8600)
May 20 11:00:04 vagrant consul[1421]:       Cluster Addr: 192.168.2.201 (LAN: 8301, WAN: 8302)
May 20 11:00:04 vagrant consul[1421]:            Encrypt: Gossip: false, TLS-Outgoing: true, TLS-Incoming: true
May 20 11:00:04 vagrant consul[1421]: ==> Log data will now stream in as it occurs:
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [DEBUG] tlsutil: Update with version 1
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [DEBUG] tlsutil: OutgoingRPCWrapper with version 1
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [INFO] serf: EventMemberJoin: client01 192.168.2.201
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [INFO] agent: Started DNS server 127.0.0.1:8600 (udp)
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [DEBUG] agent/proxy: managed Connect proxy manager started
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [INFO] agent: Started DNS server 127.0.0.1:8600 (tcp)
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [DEBUG] tlsutil: IncomingHTTPSConfig with version 1
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [INFO] agent: Started HTTPS server on [::]:8321 (tcp)
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [INFO] agent: (LAN) joining: [192.168.2.11]
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [WARN] manager: No servers available
May 20 11:00:04 vagrant consul[1421]: message repeated 55 times: [     2019/05/20 11:00:04 [WARN] manager: No servers available]
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [ERR] roots watch error: invalid type for roots response: <nil>
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [ERR] upstream:service:http-echo watch error: invalid type for service response: <nil>
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [WARN] manager: No servers available
May 20 11:00:04 vagrant consul[1421]: message repeated 15 times: [     2019/05/20 11:00:04 [WARN] manager: No servers available]
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [ERR] roots watch error: invalid type for roots response: <nil>
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [WARN] manager: No servers available
May 20 11:00:04 vagrant consul[1421]: message repeated 3 times: [     2019/05/20 11:00:04 [WARN] manager: No servers available]
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [ERR] leaf watch error: invalid type for leaf response: <nil>
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [WARN] manager: No servers available
May 20 11:00:04 vagrant consul[1421]: message repeated 11 times: [     2019/05/20 11:00:04 [WARN] manager: No servers available]
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [ERR] leaf watch error: invalid type for leaf response: <nil>
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [WARN] manager: No servers available
May 20 11:00:04 vagrant consul[1421]: message repeated 23 times: [     2019/05/20 11:00:04 [WARN] manager: No servers available]
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [DEBUG] memberlist: Initiating push/pull sync with: 192.168.2.11:8301
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [INFO] serf: EventMemberJoin: app01 192.168.2.101
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [INFO] serf: EventMemberJoin: leader01 192.168.2.11
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [WARN] memberlist: Refuting a suspect message (from: client01)
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [DEBUG] serf: Refuting an older leave intent
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [INFO] agent: (LAN) joined: 1 Err: <nil>
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [DEBUG] agent: systemd notify failed: No socket
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [INFO] agent: started state syncer
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [INFO] consul: adding server leader01 (Addr: tcp/192.168.2.11:8300) (DC: allthingscloud1)
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [DEBUG] tlsutil: OutgoingRPCConfig with version 1
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [DEBUG] acl: transition out of legacy ACL mode
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [INFO] serf: EventMemberUpdate: client01
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [DEBUG] serf: messageJoinType: client01
May 20 11:00:04 vagrant consul[1421]:     2019/05/20 11:00:04 [DEBUG] serf: messageJoinType: client01
May 20 11:00:05 vagrant consul[1421]:     2019/05/20 11:00:05 [DEBUG] serf: messageJoinType: client01
May 20 11:00:05 vagrant consul[1421]: message repeated 2 times: [     2019/05/20 11:00:05 [DEBUG] serf: messageJoinType: client01]
May 20 11:00:05 vagrant consul[1421]:     2019/05/20 11:00:05 [DEBUG] agent: Skipping remote check "serfHealth" since it is managed automatically
May 20 11:00:06 vagrant consul[1421]:     2019/05/20 11:00:06 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 11:00:06 vagrant consul[1421]:     2019/05/20 11:00:06 [WARN] agent: Service "http-echo-sidecar-proxy" registration blocked by ACLs
May 20 11:00:06 vagrant consul[1421]:     2019/05/20 11:00:06 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:06 vagrant consul[1421]:     2019/05/20 11:00:06 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 11:00:06 vagrant consul[1421]:     2019/05/20 11:00:06 [WARN] agent: Service "client" registration blocked by ACLs
May 20 11:00:06 vagrant consul[1421]:     2019/05/20 11:00:06 [WARN] agent: Check "service:client-sidecar-proxy:1" socket connection failed: dial tcp 127.
0.0.1:21000: connect: connection refused
May 20 11:00:06 vagrant consul[1421]:     2019/05/20 11:00:06 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:06 vagrant consul[1421]:     2019/05/20 11:00:06 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 11:00:06 vagrant consul[1421]:     2019/05/20 11:00:06 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 11:00:06 vagrant consul[1421]:     2019/05/20 11:00:06 [WARN] agent: Service "client-sidecar-proxy" registration blocked by ACLs
May 20 11:00:06 vagrant consul[1421]:     2019/05/20 11:00:06 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [WARN] agent: Service "http-echo" registration blocked by ACLs
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [WARN] agent: Check "service:http-echo-sidecar-proxy:1" socket connection failed: dial tcp 1
27.0.0.1:21001: connect: connection refused
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [INFO] agent: Synced node info
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [DEBUG] agent: Service "client" in sync
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [DEBUG] agent: Service "client-sidecar-proxy" in sync
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [DEBUG] agent: Service "http-echo" in sync
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [DEBUG] agent: Service "http-echo-sidecar-proxy" in sync
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [DEBUG] agent: Node info in sync
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:07 vagrant consul[1421]:     2019/05/20 11:00:07 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 11:00:08 vagrant consul[1421]:     2019/05/20 11:00:08 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 11:00:08 vagrant consul[1421]:     2019/05/20 11:00:08 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:08 vagrant consul[1421]:     2019/05/20 11:00:08 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:08 vagrant consul[1421]:     2019/05/20 11:00:08 [DEBUG] agent: Skipping remote check "serfHealth" since it is managed automatically
May 20 11:00:08 vagrant consul[1421]:     2019/05/20 11:00:08 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:08 vagrant consul[1421]:     2019/05/20 11:00:08 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 11:00:08 vagrant consul[1421]:     2019/05/20 11:00:08 [WARN] agent: Service "http-echo-sidecar-proxy" registration blocked by ACLs
May 20 11:00:09 vagrant consul[1421]:     2019/05/20 11:00:09 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 11:00:09 vagrant consul[1421]:     2019/05/20 11:00:09 [WARN] agent: Service "client" registration blocked by ACLs
May 20 11:00:09 vagrant consul[1421]:     2019/05/20 11:00:09 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:09 vagrant consul[1421]:     2019/05/20 11:00:09 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 11:00:09 vagrant consul[1421]:     2019/05/20 11:00:09 [WARN] agent: Service "client-sidecar-proxy" registration blocked by ACLs
May 20 11:00:09 vagrant consul[1421]:     2019/05/20 11:00:09 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.2.11:8300: rpc error making ca
ll: Permission denied
May 20 11:00:09 vagrant consul[1421]:     2019/05/20 11:00:09 [WARN] agent: Service "http-echo" registration blocked by ACLs
May 20 11:00:09 vagrant consul[1421]:     2019/05/20 11:00:09 [DEBUG] agent: Check "service:client-sidecar-proxy:1" in sync
May 20 11:00:09 vagrant consul[1421]:     2019/05/20 11:00:09 [DEBUG] agent: Check "service:client-sidecar-proxy:2" in sync
May 20 11:00:09 vagrant consul[1421]:     2019/05/20 11:00:09 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:1" in sync
May 20 11:00:09 vagrant consul[1421]:     2019/05/20 11:00:09 [DEBUG] agent: Check "service:http-echo-sidecar-proxy:2" in sync
May 20 11:00:09 vagrant consul[1421]:     2019/05/20 11:00:09 [DEBUG] agent: Node info in sync
May 20 11:00:11 vagrant consul[1421]:     2019/05/20 11:00:11 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:11 vagrant consul[1421]:     2019/05/20 11:00:11 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:11 vagrant consul[1421]:     2019/05/20 11:00:11 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 11:00:11 vagrant consul[1421]:     2019/05/20 11:00:11 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 11:00:11 vagrant consul[1421]:     2019/05/20 11:00:11 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:11 vagrant consul[1421]:     2019/05/20 11:00:11 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 11:00:12 vagrant consul[1421]:     2019/05/20 11:00:12 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 11:00:12 vagrant consul[1421]:     2019/05/20 11:00:12 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:12 vagrant consul[1421]:     2019/05/20 11:00:12 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:12 vagrant consul[1421]:     2019/05/20 11:00:12 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
: Permission denied
May 20 11:00:13 vagrant consul[1421]:     2019/05/20 11:00:13 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.11:8300: rpc error making cal
l: Permission denied
May 20 11:00:13 vagrant consul[1421]: message repeated 3 times: [     2019/05/20 11:00:13 [ERR] consul: "Intention.Match" RPC failed to server 192.168.2.1
1:8300: rpc error making call: Permission denied]
May 20 11:00:14 vagrant consul[1421]:     2019/05/20 11:00:14 [ERR] consul: "ConnectCA.Sign" RPC failed to server 192.168.2.11:8300: rpc error making call
```


# This is not currently working and requires further debug !!!!!!
