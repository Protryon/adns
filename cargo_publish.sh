#!/bin/bash
set -ex
here=$(realpath $(dirname "$0"))
cd "$here"

cargo publish -p adns-proto
cargo publish -p adns-zone
cargo publish -p adns-client
cargo publish -p adns-server