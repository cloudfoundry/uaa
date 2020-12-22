#!/bin/echo please source

unset_env() {
  unset HTTPS_PROXY
  unset HTTP_PROXY
  unset http_proxy
  unset https_proxy
  unset GRADLE_OPTS
  unset DEFAULT_JVM_OPTS
  unset JAVA_PROXY_OPTS
  unset PROXY_PORT
  unset PROXY_HOST
  env
}
