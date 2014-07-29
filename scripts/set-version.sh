#!/bin/bash -ex

cd `dirname $0`/..

sed -i .backup -E "s/^version=.+$/version=$1/" gradle.properties
rm gradle.properties.backup