#!/usr/bin/env bash
set -xeu

function isBootRunning() {
  LOG_FILE="boot.log"
  TARGET_LINE="Started UaaBootApplication"
  TIMEOUT=60 # Timeout in seconds

  start_time=$(date +%s)

  while true; do
    if grep -q "$TARGET_LINE" "$LOG_FILE"; then
      echo "Boot Start found in the log file."
      return 0
    fi

    current_time=$(date +%s)
    elapsed_time=$((current_time - start_time))

    if [[ "$elapsed_time" -ge "$TIMEOUT" ]]; then
      echo "Timeout reached. Boot did not start"
      return 1
    fi

    sleep 1 # Check every second
  done
}

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source $DIR/start_db_helper.sh

TESTENV="$1"
BOOT="${2:-false}"


SKIP_BOOT_RUN="-Dcargo.tests.run=true"
if [[ "${BOOT:-false}" = 'boot' ]]; then
  SKIP_BOOT_RUN="-Dcargo.tests.run=false"
fi


cat <<EOF >>/etc/hosts
127.0.0.1 testzone1.localhost
127.0.0.1 testzone2.localhost
127.0.0.1 testzone3.localhost
127.0.0.1 testzone4.localhost
127.0.0.1 testzonedoesnotexist.localhost
127.0.0.1 oidcloginit.localhost
127.0.0.1 testzoneinactive.localhost
EOF

bootDB "${DB}"

pushd $(dirname $DIR)
  /etc/init.d/slapd start
  ldapadd -Y EXTERNAL -H ldapi:/// -f ./scripts/ldap/ldap_slapd_schema.ldif
  ldapadd -x -D 'cn=admin,dc=test,dc=com' -w password -f ./scripts/ldap/ldap_slapd_data.ldif

  readonly launchBoot="nohup java -DCLOUDFOUNDRY_CONFIG_PATH=`pwd`/scripts/cargo \
                           -DSECRETS_DIR=`pwd`/scripts/cargo \
                           -Djava.security.egd=file:/dev/./urandom \
                           -Dmetrics.perRequestMetrics=true \
                           -Dserver.servlet.context-path=/uaa \
                           -Dserver.tomcat.basedir=`pwd`/scripts/boot/tomcat \
                           -Dsmtp.host=localhost \
                           -Dsmtp.port=2525 \
                           -Dspring.profiles.active=${TESTENV} \
                           -Dstatsd.enabled=true \
                           -Dfile.encoding=UTF-8 \
                           -Duser.country=US \
                           -Duser.language=en \
                           -Duser.variant -jar `pwd`/uaa/build/libs/cloudfoundry-identity-uaa-0.0.0.war > boot.log 2>&1 &"

  readonly assembleCode="./gradlew '-Dspring.profiles.active=${TESTENV}' \
            '-Djava.security.egd=file:/dev/./urandom' \
            assemble \
            --max-workers=4 \
            --no-daemon \
            --stacktrace \
            --console=plain"

  readonly integrationTestCode="./gradlew '-Dspring.profiles.active=${TESTENV}' '${SKIP_BOOT_RUN}' \
            '-Djava.security.egd=file:/dev/./urandom' \
            integrationTest \
            --no-daemon \
            --stacktrace \
            --console=plain"
  if [[ "${RUN_TESTS:-true}" = 'true' ]]; then
    eval "$assembleCode"

    if [[ "${BOOT:-false}" = 'boot' ]]; then
      eval "$launchBoot"
      echo $! > boot.pid
      if isBootRunning ; then
        echo "Boot started. Can continue to run tests."
      else
        echo "Boot did not start - failing"
        exit 1
      fi
    fi
    eval "$integrationTestCode"
    kill -9 `cat boot.pid` || true
  else
    echo "$assembleCode"
    echo "$integrationTestCode"
    bash
  fi
popd
