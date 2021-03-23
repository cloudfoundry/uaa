#!/usr/bin/env bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $(basename $0) version"
    echo "Example: $(basename $0) 2.1.1"
    exit 1
fi

set -x
set -e

cd `dirname $0`/..

sed -e "s/^version=.*/version=$1/" gradle.properties > gradle.properties.new
mv gradle.properties.new gradle.properties
