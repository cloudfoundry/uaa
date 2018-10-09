#!/usr/bin/env bash

set -eu
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function bootDB {
  db=$1

  if [ "$db" = "postgresql" ]; then
    launchDB="(/docker-entrypoint.sh postgres &> /var/log/postgres-boot.log) &"
    testConnection="psql -h localhost -U postgres -c '\conninfo' &>/dev/null"
    initDB="psql -c 'drop database if exists uaa;' -U postgres; psql -c 'create database uaa;' -U postgres; psql -c 'drop user if exists root;' --dbname=uaa -U postgres; psql -c \"create user root with superuser password 'changeme';\" --dbname=uaa -U postgres; psql -c 'show max_connections;' --dbname=uaa -U postgres;"
  elif [ "$db" = "mysql" ]  || [ "$db" = "mysql-5.6" ]; then
    launchDB="(MYSQL_ROOT_PASSWORD=changeme bash /entrypoint.sh mysqld &> /var/log/mysql-boot.log) &"
    testConnection="echo '\s;' | mysql -h 127.0.0.1 -u root --password='changeme' &>/dev/null"
    initDB="mysql -uroot -pchangeme -e 'drop database if exists uaa;'; mysql -uroot -pchangeme -e 'CREATE DATABASE uaa DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;'; mysql -uroot -pchangeme -e \"SET PASSWORD FOR 'root'@'localhost' = 'changeme';\";"
  elif [ "$db" = "sqlserver" ]; then
    launchDB="(/opt/mssql/bin/sqlservr &> /var/log/sqlserver-boot.log) &"
    testConnection="/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P 'changemeCHANGEME1234!' -d master -Q \"select 'hello'\""
    initDB="pushd $script_dir/..; ./gradlew -b mssql.gradle createSQLServerUAA; popd"
  else
    echo "skipping database"
    return 0
  fi

  echo -n "Booting $db"
  set -x
  eval "$launchDB"
  for _ in $(seq 1 120); do
    set +ex
    eval "$testConnection"
    exitcode=$?
    set -e
    if [ $exitcode -eq 0 ]; then
      echo "Connection established to $db"
      sleep 1
      eval "$initDB"
      return 0
    fi
    echo -n "."
    sleep 1
  done
  echo "Unable to connect to $db"
  exit 1
}
