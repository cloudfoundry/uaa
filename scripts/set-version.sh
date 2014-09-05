#!/bin/bash -ex

cd `dirname $0`/..

sed -i -E "s/^version=.+$/version=$1/" gradle.properties
