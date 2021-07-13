#!/usr/bin/env bash

POD_NAME=$(kubectl get pods | grep uaa | cut -d' ' -f1)
kubectl exec --stdin --tty $POD_NAME -- /bin/bash
