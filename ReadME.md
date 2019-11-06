# This is not currently working and requires further debug !!!!!!

## Prerequisites

Clone this repo and perform a vargrant up

e.g.

``` bash
git clone git@github.com:allthingsclowd/Consul_Connect_Envoy_Example.git
cd Consul_Connect_Envoy_Example
vagrant up
```

This will create a demo consul environment with one consul server (leader01) and two consul clients (app01 & client01).
The Consul `cluster` is already secured using TLS certificates and ACLs have been enabled.

# Configure the application service and clients once Consul is booted

``` bash
consul members
Node      Address             Status  Type    Build  Protocol  DC               Segment
leader01  192.168.99.11:8301   alive   server  1.5.0  2         allthingscloud1  <all>
app01     192.168.99.101:8301  alive   client  1.5.0  2         allthingscloud1  <default>
client01  192.168.99.201:8301  alive   client  1.5.0  2         allthingscloud1  <default>
```

So first let's create an ACL tokens to be used to secure the application service and the client

``` bash

vagrant ssh leader01

BOOTSTRAPACL=`cat /usr/local/bootstrap/.bootstrap_acl`
export CONSUL_HTTP_TOKEN=${BOOTSTRAPACL}
echo ${CONSUL_HTTP_TOKEN}
export CONSUL_HTTP_ADDR=https://127.0.0.1:8321
export CONSUL_CACERT=/usr/local/bootstrap/certificate-config/consul-ca.pem
export CONSUL_CLIENT_CERT=/usr/local/bootstrap/certificate-config/cli.pem
export CONSUL_CLIENT_KEY=/usr/local/bootstrap/certificate-config/cli-key.pem

create_acl_policy () {

      curl \
      -s -w "\n\n\tRESPONSE CODE :\t%{http_code}\n" \
      --request PUT \
      --cacert "/usr/local/bootstrap/certificate-config/consul-ca.pem" \
      --key "/usr/local/bootstrap/certificate-config/client-key.pem" \
      --cert "/usr/local/bootstrap/certificate-config/client.pem" \
      --header "X-Consul-Token: ${CONSUL_HTTP_TOKEN}" \
      --data \
    "{
      \"Name\": \"${1}\",
      \"Description\": \"${2}\",
      \"Rules\": \"${3}\"
      }" https://127.0.0.1:8321/v1/acl/policy
}

create_acl_policy "http-echo-policy" "HTTP Echo Service" "node_prefix \\\"\\\" { policy = \\\"write\\\"} service_prefix \\\"\\\" { policy = \\\"write\\\" intentions = \\\"write\\\" } "
```

Note: returns the following error if `allow` is used by mistake instead of `write` for the intentions vaule

``` bash
Invalid service_prefix intentions policy: acl.ServicePolicy{Name:"", Policy:"write", Sentinel:acl.Sentinel{Code:"", EnforcementLevel:""}, Intentions:"allow"}
```

``` bash


SERVICETOKEN=$(curl \
  --request PUT \
  --cacert "/usr/local/bootstrap/certificate-config/consul-ca.pem" \
  --key "/usr/local/bootstrap/certificate-config/client-key.pem" \
  --cert "/usr/local/bootstrap/certificate-config/client.pem" \
  --header "X-Consul-Token: ${CONSUL_HTTP_TOKEN}" \
  --data \
'{
    "Description": "HTTP Echo Service Token",
    "Policies": [
        {
          "Name": "http-echo-policy"
        }
    ],
    "Local": false
  }' https://127.0.0.1:8321/v1/acl/token | jq -r .SecretID)

  echo "The httpecho service Token received => ${SERVICETOKEN}"
  echo -n ${SERVICETOKEN} > /usr/local/bootstrap/.httpservicetoken_acl
  sudo chmod ugo+r /usr/local/bootstrap/.httpservicetoken_acl
  export SERVICETOKEN

```

`The httpecho service Token received => b911b6ed-0d11-7a58-9f6e-c348b3b3af3d`

We'll use this token now on the app01 node when configuring it's service definition
In another session window login to the app01 node

``` bash

vagrant ssh app01

SERVICETOKEN=`cat /usr/local/bootstrap/.httpservicetoken_acl`
export CONSUL_HTTP_TOKEN=${SERVICETOKEN}
echo ${CONSUL_HTTP_TOKEN}
export CONSUL_HTTP_ADDR=https://127.0.0.1:8321
export CONSUL_CACERT=/usr/local/bootstrap/certificate-config/consul-ca.pem
export CONSUL_CLIENT_CERT=/usr/local/bootstrap/certificate-config/cli.pem
export CONSUL_CLIENT_KEY=/usr/local/bootstrap/certificate-config/cli-key.pem

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
    --header "X-Consul-Token: ${SERVICETOKEN}" \
    --data @httpecho_service.json \
    ${CONSUL_HTTP_ADDR}/v1/agent/service/register

```

Login to the client01 and register the client service

``` bash

vagrant ssh client01

SERVICETOKEN=`cat /usr/local/bootstrap/.httpservicetoken_acl`
export CONSUL_HTTP_TOKEN=${SERVICETOKEN}
echo ${CONSUL_HTTP_TOKEN}
export CONSUL_HTTP_ADDR=https://127.0.0.1:8321
export CONSUL_CACERT=/usr/local/bootstrap/certificate-config/consul-ca.pem
export CONSUL_CLIENT_CERT=/usr/local/bootstrap/certificate-config/cli.pem
export CONSUL_CLIENT_KEY=/usr/local/bootstrap/certificate-config/cli-key.pem


  # configure http-echo service definition
  tee client4httpecho_service.json <<EOF
{
  "ID": "client",
  "Name": "client",
  "Tags": [
    "client",
    "v1"
  ],
  "Address": "127.0.0.1",
  "Port": 1234,
  "connect": { "sidecar_service": {
    "proxy": {
        "upstreams": [
          {
            "destination_name": "httpecho",
            "local_bind_port": 9091
          }
        ],
        "config": {
          "handshake_timeout_ms": 1000
        }
    }
  },
  "Meta": {
    "client_version": "1.0"
  },
  "EnableTagOverride": false

  }
}
EOF

# Register the service in consul via the local Consul agent api
sudo curl \
    -s -w "\n\n\tRESPONSE CODE :\t%{http_code}\n" \
    --request PUT \
    --cacert "/usr/local/bootstrap/certificate-config/consul-ca.pem" \
    --key "/usr/local/bootstrap/certificate-config/client-key.pem" \
    --cert "/usr/local/bootstrap/certificate-config/client.pem" \
    --header "X-Consul-Token: ${SERVICETOKEN}" \
    --data @client4httpecho_service.json \
    ${CONSUL_HTTP_ADDR}/v1/agent/service/register
```



The Consul dashboard on https://localhost:8321/ui/allthingscloud1/services should look like this ![image](https://user-images.githubusercontent.com/9472095/58022030-77b5ce80-7b04-11e9-99d4-f73bdc674051.png)

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
SERVICETOKEN=`cat /usr/local/bootstrap/.httpservicetoken_acl`

/usr/local/bin/consul connect envoy -http-addr=https://127.0.0.1:8321 -ca-file=/usr/local/bootstrap/certificate-config/consul-ca.pem -client-cert=/usr/local/bootstrap/certificate-config/cli.pem -client-key=/usr/local/bootstrap/certificate-config/cli-key.pem -token=${SERVICETOKEN} -sidecar-for httpecho -bootstrap
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
    "cluster": "httpecho",
    "id": "httpecho-sidecar-proxy"
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
                        "fixed_value": "httpecho"
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
            "value": "b911b6ed-0d11-7a58-9f6e-c348b3b3af3d"
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

Now that we can see we're getting the configured bootstrap information we're going to launch an envoy proxy this time by removing the `-bootstrap` option. I'm also going to add the `-- -l debug` to this session so that we can see what's happening - not required during normal operation

``` bash
SERVICETOKEN=`cat /usr/local/bootstrap/.httpservicetoken_acl`

/usr/local/bin/consul connect envoy -http-addr=https://127.0.0.1:8321 -ca-file=/usr/local/bootstrap/certificate-config/consul-ca.pem -client-cert=/usr/local/bootstrap/certificate-config/cli.pem -client-key=/usr/local/bootstrap/certificate-config/cli-key.pem -token=${SERVICETOKEN} -sidecar-for httpecho -- -l debug &
```

and we get a lot of scary information like this

``` bash
vagrant@app01:~$ /usr/local/bin/consul connect envoy -http-addr=https://127.0.0.1:8321 -ca-file=/usr/local/bootstrap/certificate-config/consul-ca.pem -client-cert=/usr/local/bootstrap/certificate-config/cli.pem -client-key=/usr/local/bootstrap/certificate-config/cli-key.pem -token=b911b6ed-0d11-7a58-9f6e-c348b3b3af3d -sidecar-for httpecho -- -l debug &
[2] 1772
vagrant@app01:~$ [2019-05-21 15:29:08.574][001772][info][main] [source/server/server.cc:206] initializing epoch 0 (hot restart version=disabled)
[2019-05-21 15:29:08.574][001772][info][main] [source/server/server.cc:208] statically linked extensions:
[2019-05-21 15:29:08.575][001772][info][main] [source/server/server.cc:210]   access_loggers: envoy.file_access_log,envoy.http_grpc_access_log
[2019-05-21 15:29:08.575][001772][info][main] [source/server/server.cc:213]   filters.http: envoy.buffer,envoy.cors,envoy.ext_authz,envoy.fault,envoy.filters.http.header_to_metadata,envoy.filters.http.jwt_authn,envoy.filters.http.rbac,envoy.grpc_http1_bridge,envoy.grpc_json_transcoder,envoy.grpc_web,envoy.gzip,envoy.health_check,envoy.http_dynamo_filter,envoy.ip_tagging,envoy.lua,envoy.rate_limit,envoy.router,envoy.squash
[2019-05-21 15:29:08.575][001772][info][main] [source/server/server.cc:216]   filters.listener: envoy.listener.original_dst,envoy.listener.proxy_protocol,envoy.listener.tls_inspector
[2019-05-21 15:29:08.576][001772][info][main] [source/server/server.cc:219]   filters.network: envoy.client_ssl_auth,envoy.echo,envoy.ext_authz,envoy.filters.network.dubbo_proxy,envoy.filters.network.rbac,envoy.filters.network.sni_cluster,envoy.filters.network.thrift_proxy,envoy.http_connection_manager,envoy.mongo_proxy,envoy.ratelimit,envoy.redis_proxy,envoy.tcp_proxy
[2019-05-21 15:29:08.576][001772][info][main] [source/server/server.cc:221]   stat_sinks: envoy.dog_statsd,envoy.metrics_service,envoy.stat_sinks.hystrix,envoy.statsd
[2019-05-21 15:29:08.576][001772][info][main] [source/server/server.cc:223]   tracers: envoy.dynamic.ot,envoy.lightstep,envoy.tracers.datadog,envoy.zipkin
[2019-05-21 15:29:08.576][001772][info][main] [source/server/server.cc:226]   transport_sockets.downstream: envoy.transport_sockets.alts,envoy.transport_sockets.capture,raw_buffer,tls
[2019-05-21 15:29:08.577][001772][info][main] [source/server/server.cc:229]   transport_sockets.upstream: envoy.transport_sockets.alts,envoy.transport_sockets.capture,raw_buffer,tls
[2019-05-21 15:29:08.580][001772][info][main] [source/server/server.cc:271] admin address: 127.0.0.1:19000
[2019-05-21 15:29:08.581][001772][debug][main] [source/server/overload_manager_impl.cc:171] No overload action configured for envoy.overload_actions.stop_accepting_connections.
[2019-05-21 15:29:08.582][001772][info][config] [source/server/configuration_impl.cc:50] loading 0 static secret(s)
[2019-05-21 15:29:08.583][001772][info][config] [source/server/configuration_impl.cc:56] loading 1 cluster(s)
[2019-05-21 15:29:08.587][001784][debug][grpc] [source/common/grpc/google_async_client_impl.cc:41] completionThread running
[2019-05-21 15:29:08.588][001772][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:824] adding TLS initial cluster local_agent
[2019-05-21 15:29:08.593][001772][debug][upstream] [source/common/upstream/upstream_impl.cc:634] initializing secondary cluster local_agent completed
[2019-05-21 15:29:08.594][001772][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:958] membership update for TLS cluster local_agent added 1 removed 0
[2019-05-21 15:29:08.594][001772][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:91] cm init: init complete: cluster=local_agent primary=0 secondary=0
[2019-05-21 15:29:08.594][001772][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:63] cm init: adding: cluster=local_agent primary=0 secondary=0
[2019-05-21 15:29:08.595][001772][info][upstream] [source/common/upstream/cluster_manager_impl.cc:132] cm init: initializing cds
[2019-05-21 15:29:08.595][001772][debug][upstream] [source/common/config/grpc_mux_impl.cc:137] gRPC mux subscribe for type.googleapis.com/envoy.api.v2.Cluster
[2019-05-21 15:29:08.595][001772][debug][upstream] [source/common/config/grpc_mux_impl.cc:89] No stream available to sendDiscoveryRequest for type.googleapis.com/envoy.api.v2.Cluster
[2019-05-21 15:29:08.596][001772][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-21 15:29:08.599][001772][debug][router] [source/common/router/router.cc:270] [C0][S9793904193376716991] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-21 15:29:08.600][001772][debug][router] [source/common/router/router.cc:328] [C0][S9793904193376716991] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'b911b6ed-0d11-7a58-9f6e-c348b3b3af3d'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-21 15:29:08.603][001772][debug][client] [source/common/http/codec_client.cc:26] [C0] connecting
[2019-05-21 15:29:08.604][001772][debug][connection] [source/common/network/connection_impl.cc:634] [C0] connecting to 127.0.0.1:8502
[2019-05-21 15:29:08.604][001772][debug][connection] [source/common/network/connection_impl.cc:643] [C0] connection in progress
[2019-05-21 15:29:08.604][001772][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C0] setting stream-level initial window size to 268435456
[2019-05-21 15:29:08.604][001772][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C0] updating connection-level initial window size to 268435456
[2019-05-21 15:29:08.604][001772][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-21 15:29:08.604][001772][info][config] [source/server/configuration_impl.cc:67] loading 0 listener(s)
[2019-05-21 15:29:08.605][001772][info][config] [source/server/configuration_impl.cc:92] loading tracing configuration
[2019-05-21 15:29:08.605][001772][info][config] [source/server/configuration_impl.cc:112] loading stats sink configuration
[2019-05-21 15:29:08.605][001772][info][main] [source/server/server.cc:463] starting main dispatch loop
[2019-05-21 15:29:08.605][001772][debug][connection] [source/common/network/connection_impl.cc:525] [C0] delayed connection error: 111
[2019-05-21 15:29:08.605][001772][debug][connection] [source/common/network/connection_impl.cc:183] [C0] closing socket: 0
[2019-05-21 15:29:08.605][001772][debug][client] [source/common/http/codec_client.cc:82] [C0] disconnect. resetting 0 pending requests
[2019-05-21 15:29:08.605][001772][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C0] client disconnected
[2019-05-21 15:29:08.605][001772][debug][router] [source/common/router/router.cc:481] [C0][S9793904193376716991] upstream reset
[2019-05-21 15:29:08.605][001772][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

```

It's also possible to query the envoy configuration by using envoy's admin interface 

``` bash
curl localhost:19000/config_dump
```

and then we can see the following configuration returned

``` json
vagrant@app01:~$ curl localhost:19000/config_dump
{
 "configs": [
  {
   "@type": "type.googleapis.com/envoy.admin.v2alpha.BootstrapConfigDump",
   "bootstrap": {
    "node": {
     "id": "httpecho-sidecar-proxy",
     "cluster": "httpecho",
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
          "value": "b911b6ed-0d11-7a58-9f6e-c348b3b3af3d"
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
       "fixed_value": "httpecho"
      }
     ],
     "use_all_default_tags": true
    }
   },
   "last_updated": "2019-05-21T15:29:08.579Z"
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
     "last_updated": "2019-05-21T15:29:08.588Z"
    }
   ]
  },
  {
   "@type": "type.googleapis.com/envoy.admin.v2alpha.ListenersConfigDump"
  }
 ]
}
```

_[Note-to-self :at this point the app sidecar proxy still shows as failing in Consul this maybe broken - I tried creating intentions between both client and http-echo service but this has made no difference]_

## Now we'll jump over to the client node and start the client proxy service

``` bash
exit
vagrant ssh client01
```

Let's quickly verify what the consul envoy bootstrap config looks like for this proxy

``` bash
SERVICETOKEN=`cat /usr/local/bootstrap/.httpservicetoken_acl`

/usr/local/bin/consul connect envoy -http-addr=https://127.0.0.1:8321 -ca-file=/usr/local/bootstrap/certificate-config/consul-ca.pem -client-cert=/usr/local/bootstrap/certificate-config/cli.pem -client-key=/usr/local/bootstrap/certificate-config/cli-key.pem -token=${SERVICETOKEN} -sidecar-for client -admin-bind localhost:19001  -bootstrap
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
            "value": "b911b6ed-0d11-7a58-9f6e-c348b3b3af3d"
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
SERVICETOKEN=`cat /usr/local/bootstrap/.httpservicetoken_acl`

/usr/local/bin/consul connect envoy -http-addr=https://127.0.0.1:8321 -ca-file=/usr/local/bootstrap/certificate-config/consul-ca.pem -client-cert=/usr/local/bootstrap/certificate-config/cli.pem -client-key=/usr/local/bootstrap/certificate-config/cli-key.pem -token=${SERVICETOKEN} -sidecar-for client -admin-bind localhost:19001 -- -l debug &
```

which returns the following logs

``` bash
vagrant@client01:~$ [2019-05-21 15:56:39.338][001823][info][main] [source/server/server.cc:206] initializing epoch 0 (hot restart version=disabled)
[2019-05-21 15:56:39.338][001823][info][main] [source/server/server.cc:208] statically linked extensions:
[2019-05-21 15:56:39.338][001823][info][main] [source/server/server.cc:210]   access_loggers: envoy.file_access_log,envoy.http_grpc_access_log
[2019-05-21 15:56:39.339][001823][info][main] [source/server/server.cc:213]   filters.http: envoy.buffer,envoy.cors,envoy.ext_authz,envoy.fault,envoy.filters.http.header_to_metadata,envoy.filters.http.jwt_authn,envoy.filters.http.rbac,envoy.grpc_http1_bridge,envoy.grpc_json_transcoder,envoy.grpc_web,envoy.gzip,envoy.health_check,envoy.http_dynamo_filter,envoy.ip_tagging,envoy.lua,envoy.rate_limit,envoy.router,envoy.squash
[2019-05-21 15:56:39.339][001823][info][main] [source/server/server.cc:216]   filters.listener: envoy.listener.original_dst,envoy.listener.proxy_protocol,envoy.listener.tls_inspector
[2019-05-21 15:56:39.339][001823][info][main] [source/server/server.cc:219]   filters.network: envoy.client_ssl_auth,envoy.echo,envoy.ext_authz,envoy.filters.network.dubbo_proxy,envoy.filters.network.rbac,envoy.filters.network.sni_cluster,envoy.filters.network.thrift_proxy,envoy.http_connection_manager,envoy.mongo_proxy,envoy.ratelimit,envoy.redis_proxy,envoy.tcp_proxy
[2019-05-21 15:56:39.340][001823][info][main] [source/server/server.cc:221]   stat_sinks: envoy.dog_statsd,envoy.metrics_service,envoy.stat_sinks.hystrix,envoy.statsd
[2019-05-21 15:56:39.340][001823][info][main] [source/server/server.cc:223]   tracers: envoy.dynamic.ot,envoy.lightstep,envoy.tracers.datadog,envoy.zipkin
[2019-05-21 15:56:39.340][001823][info][main] [source/server/server.cc:226]   transport_sockets.downstream: envoy.transport_sockets.alts,envoy.transport_sockets.capture,raw_buffer,tls
[2019-05-21 15:56:39.341][001823][info][main] [source/server/server.cc:229]   transport_sockets.upstream: envoy.transport_sockets.alts,envoy.transport_sockets.capture,raw_buffer,tls
[2019-05-21 15:56:39.343][001823][info][main] [source/server/server.cc:271] admin address: 127.0.0.1:19000
[2019-05-21 15:56:39.344][001823][debug][main] [source/server/overload_manager_impl.cc:171] No overload action configured for envoy.overload_actions.stop_accepting_connections.
[2019-05-21 15:56:39.345][001823][info][config] [source/server/configuration_impl.cc:50] loading 0 static secret(s)
[2019-05-21 15:56:39.345][001823][info][config] [source/server/configuration_impl.cc:56] loading 1 cluster(s)
[2019-05-21 15:56:39.351][001835][debug][grpc] [source/common/grpc/google_async_client_impl.cc:41] completionThread running
[2019-05-21 15:56:39.353][001823][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:824] adding TLS initial cluster local_agent
[2019-05-21 15:56:39.360][001823][debug][upstream] [source/common/upstream/upstream_impl.cc:634] initializing secondary cluster local_agent completed
[2019-05-21 15:56:39.361][001823][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:958] membership update for TLS cluster local_agent added 1 removed 0
[2019-05-21 15:56:39.361][001823][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:91] cm init: init complete: cluster=local_agent primary=0 secondary=0
[2019-05-21 15:56:39.361][001823][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:63] cm init: adding: cluster=local_agent primary=0 secondary=0
[2019-05-21 15:56:39.362][001823][info][upstream] [source/common/upstream/cluster_manager_impl.cc:132] cm init: initializing cds
[2019-05-21 15:56:39.362][001823][debug][upstream] [source/common/config/grpc_mux_impl.cc:137] gRPC mux subscribe for type.googleapis.com/envoy.api.v2.Cluster
[2019-05-21 15:56:39.363][001823][debug][upstream] [source/common/config/grpc_mux_impl.cc:89] No stream available to sendDiscoveryRequest for type.googleapis.com/envoy.api.v2.Cluster
[2019-05-21 15:56:39.364][001823][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-21 15:56:39.367][001823][debug][router] [source/common/router/router.cc:270] [C0][S17189326826573981155] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-21 15:56:39.368][001823][debug][router] [source/common/router/router.cc:328] [C0][S17189326826573981155] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'b911b6ed-0d11-7a58-9f6e-c348b3b3af3d'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

[2019-05-21 15:56:39.371][001823][debug][client] [source/common/http/codec_client.cc:26] [C0] connecting
[2019-05-21 15:56:39.371][001823][debug][connection] [source/common/network/connection_impl.cc:634] [C0] connecting to 127.0.0.1:8502
[2019-05-21 15:56:39.371][001823][debug][connection] [source/common/network/connection_impl.cc:643] [C0] connection in progress
[2019-05-21 15:56:39.371][001823][debug][http2] [source/common/http/http2/codec_impl.cc:721] [C0] setting stream-level initial window size to 268435456
[2019-05-21 15:56:39.372][001823][debug][http2] [source/common/http/http2/codec_impl.cc:743] [C0] updating connection-level initial window size to 268435456
[2019-05-21 15:56:39.372][001823][debug][pool] [source/common/http/conn_pool_base.cc:20] queueing request due to no available connections
[2019-05-21 15:56:39.372][001823][info][config] [source/server/configuration_impl.cc:67] loading 0 listener(s)
[2019-05-21 15:56:39.372][001823][info][config] [source/server/configuration_impl.cc:92] loading tracing configuration
[2019-05-21 15:56:39.372][001823][info][config] [source/server/configuration_impl.cc:112] loading stats sink configuration
[2019-05-21 15:56:39.372][001823][info][main] [source/server/server.cc:463] starting main dispatch loop
[2019-05-21 15:56:39.373][001823][debug][connection] [source/common/network/connection_impl.cc:525] [C0] delayed connection error: 111
[2019-05-21 15:56:39.373][001823][debug][connection] [source/common/network/connection_impl.cc:183] [C0] closing socket: 0
[2019-05-21 15:56:39.373][001823][debug][client] [source/common/http/codec_client.cc:82] [C0] disconnect. resetting 0 pending requests
[2019-05-21 15:56:39.373][001823][debug][pool] [source/common/http/http2/conn_pool.cc:136] [C0] client disconnected
[2019-05-21 15:56:39.373][001823][debug][router] [source/common/router/router.cc:481] [C0][S17189326826573981155] upstream reset
[2019-05-21 15:56:39.373][001823][debug][http] [source/common/http/async_client_impl.cc:93] async http request response headers (end_stream=true):
':status', '200'
'content-type', 'application/grpc'
'grpc-status', '14'
'grpc-message', 'upstream connect error or disconnect/reset before headers'

[2019-05-21 15:56:39.373][001823][warning][upstream] [source/common/config/grpc_mux_impl.cc:268] gRPC config stream closed: 14, upstream connect error or disconnect/reset before headers
[2019-05-21 15:56:39.373][001823][debug][pool] [source/common/http/http2/conn_pool.cc:160] [C0] destroying primary client
[2019-05-21 15:56:39.578][001823][debug][upstream] [source/common/config/grpc_mux_impl.cc:48] Establishing new gRPC bidi stream for rpc StreamAggregatedResources(stream .envoy.api.v2.DiscoveryRequest) returns (stream .envoy.api.v2.DiscoveryResponse);

[2019-05-21 15:56:39.579][001823][debug][router] [source/common/router/router.cc:270] [C0][S17628408696213668] cluster 'local_agent' match for URL '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
[2019-05-21 15:56:39.579][001823][debug][router] [source/common/router/router.cc:328] [C0][S17628408696213668] router decoding headers:
':method', 'POST'
':path', '/envoy.service.discovery.v2.AggregatedDiscoveryService/StreamAggregatedResources'
':authority', 'local_agent'
':scheme', 'http'
'te', 'trailers'
'content-type', 'application/grpc'
'x-consul-token', 'b911b6ed-0d11-7a58-9f6e-c348b3b3af3d'
'x-envoy-internal', 'true'
'x-forwarded-for', '10.0.2.15'

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
          "value": "b911b6ed-0d11-7a58-9f6e-c348b3b3af3d"
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
   "last_updated": "2019-05-21T15:56:39.342Z"
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
     "last_updated": "2019-05-21T15:56:39.353Z"
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

Listening ports

``` bash
vagrant@client01:~$ sudo lsof -i -P -n | grep LISTEN
systemd-r  482 systemd-resolve   13u  IPv4  15611      0t0  TCP 127.0.0.53:53 (LISTEN)
rpcbind    483            root    8u  IPv4  15628      0t0  TCP *:111 (LISTEN)
rpcbind    483            root   11u  IPv6  15631      0t0  TCP *:111 (LISTEN)
sshd       572            root    3u  IPv4  17358      0t0  TCP *:22 (LISTEN)
sshd       572            root    4u  IPv6  17369      0t0  TCP *:22 (LISTEN)
consul    1419          consul    5u  IPv4  24092      0t0  TCP 192.168.99.201:8301 (LISTEN)
consul    1419          consul    7u  IPv4  24095      0t0  TCP 127.0.0.1:8600 (LISTEN)
consul    1419          consul    9u  IPv6  24101      0t0  TCP *:8321 (LISTEN)
envoy     1823         vagrant    9u  IPv4  26982      0t0  TCP 127.0.0.1:19000 (LISTEN)
```

``` bash
vagrant@leader01:~$ sudo lsof -i -P -n | grep LISTEN
rpcbind    471            root    8u  IPv4  15630      0t0  TCP *:111 (LISTEN)
rpcbind    471            root   11u  IPv6  15633      0t0  TCP *:111 (LISTEN)
systemd-r  472 systemd-resolve   13u  IPv4  15610      0t0  TCP 127.0.0.53:53 (LISTEN)
sshd       560            root    3u  IPv4  17336      0t0  TCP *:22 (LISTEN)
sshd       560            root    4u  IPv6  17347      0t0  TCP *:22 (LISTEN)
consul    1650          consul    3u  IPv4  24892      0t0  TCP 192.168.99.11:8300 (LISTEN)
consul    1650          consul    7u  IPv4  24893      0t0  TCP 192.168.99.11:8302 (LISTEN)
consul    1650          consul   10u  IPv4  24895      0t0  TCP 192.168.99.11:8301 (LISTEN)
consul    1650          consul   13u  IPv4  24901      0t0  TCP 127.0.0.1:8600 (LISTEN)
consul    1650          consul   14u  IPv6  24906      0t0  TCP *:8321 (LISTEN)
consul    1650          consul   15u  IPv4  24908      0t0  TCP 127.0.0.1:8502 (LISTEN)
```

``` bash
 sudo lsof -i -P -n | grep LISTEN
rpcbind    472            root    8u  IPv4  15555      0t0  TCP *:111 (LISTEN)
rpcbind    472            root   11u  IPv6  15558      0t0  TCP *:111 (LISTEN)
systemd-r  473 systemd-resolve   13u  IPv4  15610      0t0  TCP 127.0.0.53:53 (LISTEN)
sshd       560            root    3u  IPv4  17217      0t0  TCP *:22 (LISTEN)
sshd       560            root    4u  IPv6  17231      0t0  TCP *:22 (LISTEN)
consul    1412          consul    5u  IPv4  24037      0t0  TCP 192.168.99.101:8301 (LISTEN)
consul    1412          consul    8u  IPv4  24041      0t0  TCP 127.0.0.1:8600 (LISTEN)
consul    1412          consul    9u  IPv6  24046      0t0  TCP *:8321 (LISTEN)
http-echo 1726         vagrant    3u  IPv4  25931      0t0  TCP 127.0.0.1:9090 (LISTEN)
envoy     1772         vagrant    9u  IPv4  26229      0t0  TCP 127.0.0.1:19000 (LISTEN)
```

# Consul Logs

## Consul server - leader01

```bash
vagrant@leader01:~$ systemctl status consul
● consul.service - HashiCorp Consul Server SD & KV Service
   Loaded: loaded (/etc/systemd/system/consul.service; disabled; vendor preset: enabled)
   Active: active (running) since Tue 2019-05-21 14:28:44 UTC; 2h 4min ago
  Process: 1649 ExecStartPre=/bin/chown -R consul:consul /var/run/consul (code=exited, status=0/SUCCESS)
  Process: 1648 ExecStartPre=/bin/mkdir -p /var/run/consul (code=exited, status=0/SUCCESS)
 Main PID: 1650 (consul)
    Tasks: 9 (limit: 1113)
   CGroup: /system.slice/consul.service
           └─1650 /usr/local/bin/consul agent -server -log-level=debug -ui -client=127.0.0.1 -bind=192.168
vagrant@leader01:~

sudo grep -E 'consul|envoy' /var/log/syslog | grep -i -E 'err|join' | grep -v 'Skipping self join check'

vagrant@leader01:~$ sudo grep -E 'consul|envoy' /var/log/syslog | grep -i -E 'err|join' | grep -v 'Skipping self join check'
May 21 14:28:13 vagrant consul[1355]:     2019/05/21 14:28:13 [INFO] serf: EventMemberJoin: leader01.allthingscloud1 192.168.99.11
May 21 14:28:13 vagrant consul[1355]:     2019/05/21 14:28:13 [INFO] serf: EventMemberJoin: leader01 192.168.99.11
May 21 14:28:13 vagrant consul[1355]:     2019/05/21 14:28:13 [INFO] consul: Handled member-join event for server "leader01.allthingscloud1" in area "wan"
May 21 14:28:18 vagrant consul[1355]:     2019/05/21 14:28:18 [INFO] consul: member 'leader01' joined, marking health alive
May 21 14:28:28 vagrant consul[1355]:     2019/05/21 14:28:28 [DEBUG] http: Request PUT /v1/kv/development/terraform_version (1.415207ms) from=127.0.0.1:53156
May 21 14:28:29 vagrant consul[1611]:     2019/05/21 14:28:29 [INFO] serf: EventMemberJoin: leader01.allthingscloud1 192.168.99.11
May 21 14:28:29 vagrant consul[1611]:     2019/05/21 14:28:29 [INFO] serf: EventMemberJoin: leader01 192.168.99.11
May 21 14:28:29 vagrant consul[1611]:     2019/05/21 14:28:29 [WARN] serf: Failed to re-join any previously known node
May 21 14:28:29 vagrant consul[1611]:     2019/05/21 14:28:29 [WARN] serf: Failed to re-join any previously known node
May 21 14:28:29 vagrant consul[1611]:     2019/05/21 14:28:29 [INFO] consul: Handled member-join event for server "leader01.allthingscloud1" in area "wan"
May 21 14:28:37 vagrant consul[1611]:     2019/05/21 14:28:37 [ERR] agent: failed to sync remote state: No cluster leader
May 21 14:28:45 vagrant consul[1650]:     2019/05/21 14:28:45 [INFO] serf: EventMemberJoin: leader01.allthingscloud1 192.168.99.11
May 21 14:28:45 vagrant consul[1650]:     2019/05/21 14:28:45 [INFO] serf: EventMemberJoin: leader01 192.168.99.11
May 21 14:28:45 vagrant consul[1650]:     2019/05/21 14:28:45 [WARN] serf: Failed to re-join any previously known node
May 21 14:28:45 vagrant consul[1650]:     2019/05/21 14:28:45 [WARN] serf: Failed to re-join any previously known node
May 21 14:28:45 vagrant consul[1650]:     2019/05/21 14:28:45 [INFO] consul: Handled member-join event for server "leader01.allthingscloud1" in area "wan"
May 21 14:28:52 vagrant consul[1650]:     2019/05/21 14:28:52 [ERR] agent: failed to sync remote state: No cluster leader
May 21 14:29:00 vagrant consul[1650]:     2019/05/21 14:29:00 [DEBUG] http: Request PUT /v1/kv/development/terraform_version (1.460408ms) from=127.0.0.1:53224
May 21 14:29:44 vagrant consul[1650]:     2019/05/21 14:29:44 [INFO] serf: EventMemberJoin: app01 192.168.99.101
May 21 14:29:44 vagrant consul[1650]:     2019/05/21 14:29:44 [INFO] consul: member 'app01' joined, marking health alive
May 21 14:29:44 vagrant consul[1650]:     2019/05/21 14:29:44 [DEBUG] serf: messageJoinType: app01
May 21 14:29:44 vagrant consul[1650]:     2019/05/21 14:29:44 [DEBUG] serf: messageJoinType: app01
May 21 14:29:45 vagrant consul[1650]:     2019/05/21 14:29:45 [DEBUG] serf: messageJoinType: app01
May 21 14:29:45 vagrant consul[1650]:     2019/05/21 14:29:45 [DEBUG] serf: messageJoinType: app01
May 21 14:30:08 vagrant consul[1650]:     2019/05/21 14:30:08 [INFO] serf: EventMemberJoin: app01 192.168.99.101
May 21 14:30:08 vagrant consul[1650]:     2019/05/21 14:30:08 [DEBUG] serf: messageJoinType: app01
May 21 14:30:08 vagrant consul[1650]:     2019/05/21 14:30:08 [DEBUG] serf: messageJoinType: app01
May 21 14:30:08 vagrant consul[1650]:     2019/05/21 14:30:08 [INFO] consul: member 'app01' joined, marking health alive
May 21 14:30:09 vagrant consul[1650]:     2019/05/21 14:30:09 [DEBUG] serf: messageJoinType: app01
May 21 14:30:09 vagrant consul[1650]: message repeated 5 times: [     2019/05/21 14:30:09 [DEBUG] serf: messageJoinType: app01]
May 21 14:31:12 vagrant consul[1650]:     2019/05/21 14:31:12 [INFO] serf: EventMemberJoin: client01 192.168.99.201
May 21 14:31:12 vagrant consul[1650]:     2019/05/21 14:31:12 [INFO] consul: member 'client01' joined, marking health alive
May 21 14:31:13 vagrant consul[1650]:     2019/05/21 14:31:13 [DEBUG] serf: messageJoinType: client01
May 21 14:31:13 vagrant consul[1650]:     2019/05/21 14:31:13 [DEBUG] serf: messageJoinType: client01
May 21 14:31:13 vagrant consul[1650]: message repeated 2 times: [     2019/05/21 14:31:13 [DEBUG] serf: messageJoinType: client01]
May 21 14:31:34 vagrant consul[1650]:     2019/05/21 14:31:34 [INFO] serf: EventMemberJoin: client01 192.168.99.201
May 21 14:31:34 vagrant consul[1650]:     2019/05/21 14:31:34 [DEBUG] serf: messageJoinType: client01
May 21 14:31:34 vagrant consul[1650]:     2019/05/21 14:31:34 [DEBUG] serf: messageJoinType: client01
May 21 14:31:34 vagrant consul[1650]:     2019/05/21 14:31:34 [INFO] consul: member 'client01' joined, marking health alive
May 21 14:31:34 vagrant consul[1650]:     2019/05/21 14:31:34 [DEBUG] serf: messageJoinType: client01
May 21 14:31:34 vagrant consul[1650]: message repeated 3 times: [     2019/05/21 14:31:34 [DEBUG] serf: messageJoinType: client01]
May 21 14:37:52 vagrant consul[1650]:     2019/05/21 14:37:52 [ERR] http: Request GET /v1/internal/ui/services?dc=allthingscloud1, error: ACL not found from=10.0.2.2:49493
May 21 14:37:52 vagrant consul[1650]:     2019/05/21 14:37:52 [ERR] http: Request GET /v1/acl/tokens?dc=allthingscloud1, error: Permission denied from=10.0.2.2:49493
May 21 14:40:15 vagrant consul[1650]:     2019/05/21 14:40:15 [ERR] http: Request PUT /v1/acl/policy, error: Invalid service_prefix intentions policy: acl.ServicePolicy{Name:"", Policy:"write", Sentinel:acl.Sentinel{Code:"", EnforcementLevel:""}, Intentions:"allow"} from=127.0.0.1:53316
May 21 14:47:48 vagrant consul[1650]:     2019/05/21 14:47:48 [ERR] http: Request PUT /v1/acl/policy, error: Invalid service_prefix intentions policy: acl.ServicePolicy{Name:"", Policy:"write", Sentinel:acl.Sentinel{Code:"", EnforcementLevel:""}, Intentions:"allow all"} from=127.0.0.1:53348
May 21 14:52:40 vagrant consul[1650]:     2019/05/21 14:52:40 [ERR] http: Request PUT /v1/acl/policy, error: Invalid Policy: A Policy with Name "http-echo-policy" already exists from=127.0.0.1:53372
May 21 14:53:39 vagrant consul[1650]:     2019/05/21 14:53:39 [ERR] http: Request PUT /v1/acl/policy, error: Invalid service_prefix intentions policy: acl.ServicePolicy{Name:"", Policy:"write", Sentinel:acl.Sentinel{Code:"", EnforcementLevel:""}, Intentions:"allow"} from=127.0.0.1:53378
May 21 14:58:22 vagrant consul[1650]:     2019/05/21 14:58:22 [ERR] http: Request PUT /v1/acl/policy, error: Invalid Policy: A Policy with Name "http-echo-policy2" already exists from=127.0.0.1:53402
vagrant@leader01:~$
```

## Consul server - app01

``` bash
vagrant@app01:~$ systemctl status consul
● consul.service - HashiCorp Consul Agent Service
   Loaded: loaded (/etc/systemd/system/consul.service; disabled; vendor preset: enabled)
   Active: active (running) since Tue 2019-05-21 14:30:08 UTC; 1h 52min ago
  Process: 1411 ExecStartPre=/bin/chown -R consul:consul /var/run/consul (code=exited, status=0/SUCCESS)
  Process: 1410 ExecStartPre=/bin/mkdir -p /var/run/consul (code=exited, status=0/SUCCESS)
 Main PID: 1412 (consul)
    Tasks: 8 (limit: 1113)
   CGroup: /system.slice/consul.service
           └─1412 /usr/local/bin/consul agent -log-level=debug -client=127.0.0.1 -bind=192.168.99.101 -conf
lines 1-9/9 (END)

vagrant@app01:~$ sudo grep -E 'consul|envoy' /var/log/syslog | grep -i -E 'err|join'
May 21 14:29:44 vagrant consul[1347]: ==> Joining cluster...
May 21 14:29:44 vagrant consul[1347]:     Join completed. Synced with 1 initial agents
May 21 14:29:44 vagrant consul[1347]:     2019/05/21 14:29:44 [INFO] serf: EventMemberJoin: app01 192.168.99.101
May 21 14:29:44 vagrant consul[1347]:     2019/05/21 14:29:44 [INFO] agent: (LAN) joining: [192.168.99.11]
May 21 14:29:44 vagrant consul[1347]:     2019/05/21 14:29:44 [INFO] serf: EventMemberJoin: leader01 192.168.99.11
May 21 14:29:44 vagrant consul[1347]:     2019/05/21 14:29:44 [INFO] agent: (LAN) joined: 1 Err: <nil>
May 21 14:29:44 vagrant consul[1347]:     2019/05/21 14:29:44 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.99.11:8300: rpc error making call: Permission denied
May 21 14:29:45 vagrant consul[1347]:     2019/05/21 14:29:45 [DEBUG] serf: messageJoinType: app01
May 21 14:29:45 vagrant consul[1347]:     2019/05/21 14:29:45 [DEBUG] serf: messageJoinType: app01
May 21 14:29:45 vagrant consul[1347]:     2019/05/21 14:29:45 [DEBUG] serf: messageJoinType: app01
May 21 14:29:45 vagrant consul[1347]:     2019/05/21 14:29:45 [DEBUG] serf: messageJoinType: app01
May 21 14:29:47 vagrant consul[1347]:     2019/05/21 14:29:47 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.99.11:8300: rpc error making call: Permission denied
May 21 14:30:08 vagrant consul[1347]:     2019/05/21 14:30:08 [ERR] memberlist: Failed to send ping: write udp 192.168.99.101:8301->192.168.99.11:8301: use of closed network connection
May 21 14:30:09 vagrant consul[1412]: ==> Joining cluster...
May 21 14:30:09 vagrant consul[1412]:     Join completed. Synced with 1 initial agents
May 21 14:30:09 vagrant consul[1412]:     2019/05/21 14:30:08 [INFO] serf: EventMemberJoin: app01 192.168.99.101
May 21 14:30:09 vagrant consul[1412]:     2019/05/21 14:30:09 [INFO] agent: (LAN) joining: [192.168.99.11]
May 21 14:30:09 vagrant consul[1412]:     2019/05/21 14:30:09 [INFO] serf: EventMemberJoin: leader01 192.168.99.11
May 21 14:30:09 vagrant consul[1412]:     2019/05/21 14:30:09 [INFO] agent: (LAN) joined: 1 Err: <nil>
May 21 14:30:09 vagrant consul[1412]:     2019/05/21 14:30:09 [DEBUG] serf: messageJoinType: app01
May 21 14:30:09 vagrant consul[1412]: message repeated 3 times: [     2019/05/21 14:30:09 [DEBUG] serf: messageJoinType: app01]
May 21 14:30:24 vagrant consul[1412]:     2019/05/21 14:30:24 [DEBUG] http: Request PUT /v1/kv/development/terraform_version (2.196139ms) from=127.0.0.1:37746
May 21 14:31:13 vagrant consul[1412]:     2019/05/21 14:31:13 [INFO] serf: EventMemberJoin: client01 192.168.99.201
May 21 14:31:13 vagrant consul[1412]:     2019/05/21 14:31:13 [DEBUG] serf: messageJoinType: client01
May 21 14:31:13 vagrant consul[1412]: message repeated 3 times: [     2019/05/21 14:31:13 [DEBUG] serf: messageJoinType: client01]
May 21 14:31:34 vagrant consul[1412]:     2019/05/21 14:31:34 [INFO] serf: EventMemberJoin: client01 192.168.99.201
May 21 14:31:34 vagrant consul[1412]:     2019/05/21 14:31:34 [DEBUG] serf: messageJoinType: client01
May 21 14:31:34 vagrant consul[1412]: message repeated 5 times: [     2019/05/21 14:31:34 [DEBUG] serf: messageJoinType: client01]
vagrant@app01:~$

```

## Consul server - client01

```bash
vagrant@client01:~$ systemctl status consul
● consul.service - HashiCorp Consul Agent Service
   Loaded: loaded (/etc/systemd/system/consul.service; disabled; vendor preset: enabled)
   Active: active (running) since Tue 2019-05-21 14:31:34 UTC; 2h 9min ago
  Process: 1418 ExecStartPre=/bin/chown -R consul:consul /var/run/consul (code=exited, status=0/SUCCESS)
  Process: 1417 ExecStartPre=/bin/mkdir -p /var/run/consul (code=exited, status=0/SUCCESS)
 Main PID: 1419 (consul)
    Tasks: 8 (limit: 1113)
   CGroup: /system.slice/consul.service
           └─1419 /usr/local/bin/consul agent -log-level=debug -client=127.0.0.1 -bind=192.168.99.201 -conf
vagrant@client01:~$
vagrant@client01:~$ sudo grep -E 'consul|envoy' /var/log/syslog | grep -i -E 'err|join'
May 21 14:31:13 vagrant consul[1356]: ==> Joining cluster...
May 21 14:31:13 vagrant consul[1356]:     Join completed. Synced with 1 initial agents
May 21 14:31:13 vagrant consul[1356]:     2019/05/21 14:31:13 [INFO] serf: EventMemberJoin: client01 192.168.99.201
May 21 14:31:13 vagrant consul[1356]:     2019/05/21 14:31:13 [INFO] agent: (LAN) joining: [192.168.99.11]
May 21 14:31:13 vagrant consul[1356]:     2019/05/21 14:31:13 [INFO] serf: EventMemberJoin: leader01 192.168.99.11
May 21 14:31:13 vagrant consul[1356]:     2019/05/21 14:31:13 [INFO] serf: EventMemberJoin: app01 192.168.99.101
May 21 14:31:13 vagrant consul[1356]:     2019/05/21 14:31:13 [INFO] agent: (LAN) joined: 1 Err: <nil>
May 21 14:31:13 vagrant consul[1356]:     2019/05/21 14:31:13 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.99.11:8300: rpc error making call: Permission denied
May 21 14:31:13 vagrant consul[1356]:     2019/05/21 14:31:13 [DEBUG] serf: messageJoinType: client01
May 21 14:31:13 vagrant consul[1356]:     2019/05/21 14:31:13 [ERR] consul: "Catalog.Register" RPC failed to server 192.168.99.11:8300: rpc error making call: Permission denied
May 21 14:31:13 vagrant consul[1356]:     2019/05/21 14:31:13 [DEBUG] serf: messageJoinType: client01
May 21 14:31:13 vagrant consul[1356]: message repeated 2 times: [     2019/05/21 14:31:13 [DEBUG] serf: messageJoinType: client01]
May 21 14:31:28 vagrant consul[1356]:     2019/05/21 14:31:28 [ERR] consul: "Coordinate.Update" RPC failed to server 192.168.99.11:8300: rpc error making call: Permission denied
May 21 14:31:34 vagrant consul[1356]:     2019/05/21 14:31:34 [ERR] memberlist: Failed to send ping: write udp 192.168.99.201:8301->192.168.99.11:8301: use of closed network connection
May 21 14:31:34 vagrant consul[1419]: ==> Joining cluster...
May 21 14:31:34 vagrant consul[1419]:     Join completed. Synced with 1 initial agents
May 21 14:31:34 vagrant consul[1419]:     2019/05/21 14:31:34 [INFO] serf: EventMemberJoin: client01 192.168.99.201
May 21 14:31:34 vagrant consul[1419]:     2019/05/21 14:31:34 [INFO] agent: (LAN) joining: [192.168.99.11]
May 21 14:31:34 vagrant consul[1419]:     2019/05/21 14:31:34 [INFO] serf: EventMemberJoin: app01 192.168.99.101
May 21 14:31:34 vagrant consul[1419]:     2019/05/21 14:31:34 [INFO] serf: EventMemberJoin: leader01 192.168.99.11
May 21 14:31:34 vagrant consul[1419]:     2019/05/21 14:31:34 [INFO] agent: (LAN) joined: 1 Err: <nil>
May 21 14:31:34 vagrant consul[1419]:     2019/05/21 14:31:34 [DEBUG] serf: messageJoinType: client01
May 21 14:31:34 vagrant consul[1419]: message repeated 3 times: [     2019/05/21 14:31:34 [DEBUG] serf: messageJoinType: client01]
May 21 14:31:49 vagrant consul[1419]:     2019/05/21 14:31:49 [DEBUG] http: Request PUT /v1/kv/development/terraform_version (1.760711ms) from=127.0.0.1:50088
```


# This is not currently working and requires further debug !!!!!!
