#!/usr/bin/env bash

set -e
set -x

. /opt/yocto-sdk/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
rustup target add armv7-unknown-linux-gnueabihf
cargo build
cargo build --example udp-link
cargo build --example kaonic-client
cargo build --example kaonic-mesh
cargo build --example kaonic-tcp-mesh

exit 0
