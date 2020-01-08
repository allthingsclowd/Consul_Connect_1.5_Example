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

generate_service_token () {
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
    vault kv put kv/development/SERVICETOKEN value=${SERVICETOKEN}
}

setup_environment
create_acl_policy "http-echo-policy" "HTTP Echo Service" "node_prefix \\\"\\\" { policy = \\\"write\\\"} service_prefix \\\"\\\" { policy = \\\"write\\\" intentions = \\\"write\\\" } "
generate_service_token
