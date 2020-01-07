#!/usr/bin/env bash

set -x

install_demo_app() {
  which http-echo &>/dev/null || {
    pushd /usr/local/bin
    sudo wget -q https://github.com/hashicorp/http-echo/releases/download/v0.2.3/http-echo_0.2.3_linux_amd64.zip
    sudo unzip http-echo_0.2.3_linux_amd64.zip
    chmod +x http-echo
    rm http-echo_0.2.3_linux_amd64.zip
    popd
  }
}

install_demo_app