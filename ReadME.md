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

# This is not currently working and requires further debug !!!!!!
