#!/bin/bash

cargo run -- -c conf/nodeA.conf > /dev/null &
cargo run -- -c conf/nodeB.conf > /dev/null &

