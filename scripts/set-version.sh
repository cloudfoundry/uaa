#!/bin/bash -ex

cd `dirname $0`/..

sed -e "s/^version=.*/version=$1/" gradle.properties > gradle.properties.new
mv gradle.properties.new gradle.properties