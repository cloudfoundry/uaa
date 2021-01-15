#!/usr/bin/env bash

ytt \
    -f templates \
    -f addons \
    --data-value-yaml admin.client_secret=adminsecret \
    | kubectl apply -f -
