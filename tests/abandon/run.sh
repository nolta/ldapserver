#!/bin/sh
set -eu

go run server.go &
server_pid=$!

on_exit() {
    status=$?
    # if the server is dead, that's an error
    if !kill -0 $server_pid 2>/dev/null; then
        echo "abandon test failed: server is dead" >&2
        status=1
    fi
    kill $server_pid
    return $status
}
trap "on_exit" EXIT

python3 client.py
