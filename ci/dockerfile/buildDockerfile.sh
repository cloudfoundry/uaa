#!/usr/bin/env bash

rm -f Dockerfile
cat _FROM_Dockerfile [^_]*Dockerfile _cleanup_Dockerfile > Dockerfile
