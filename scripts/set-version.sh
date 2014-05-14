#!/bin/bash -ex

cd `dirname $0`/..

mvn versions:set -DgenerateBackupPoms=false -DnewVersion=$1
