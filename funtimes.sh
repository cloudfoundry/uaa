#!/usr/bin/env bash

set -x

DIR=$(cat uaa/build/reports/tests/uaa-server.log | tr -d 000 | grep -oe "\/private.*uaa-8080" - | head -1 | cat -)
echo $DIR
tail -f $DIR/logs/uaa.log
