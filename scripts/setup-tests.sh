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

install_chromedriver() {
  wget --quiet 'https://www.googleapis.com/download/storage/v1/b/chromium-browser-snapshots/o/Linux_x64%2F665006%2Fchromedriver_linux64.zip?generation=1559267957115896&alt=media'
  wget --quiet 'https://www.googleapis.com/download/storage/v1/b/chromium-browser-snapshots/o/Linux_x64%2F665006%2Fchrome-linux.zip?generation=1559267949433976&alt=media'
  unzip -o 'Linux_x64%2F665006%2Fchromedriver_linux64.zip?generation=1559267957115896&alt=media'
  unzip -o 'Linux_x64%2F665006%2Fchrome-linux.zip?generation=1559267949433976&alt=media'
  ln -s $PWD/chromedriver_linux64/chromedriver /usr/bin/
  ln -s $PWD/chrome-linux/chrome /usr/bin/
  chromedriver --version
  chrome --version
}