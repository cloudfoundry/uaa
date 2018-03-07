#!/usr/bin/env bash

set -xeu

function bootDB {
  db=$1

  if [ "$db" = "postgresql" ]; then
    launchDB="(/docker-entrypoint.sh postgres &> /var/log/postgres-boot.log) &"
    testConnection="psql -h localhost -U postgres -c '\conninfo' &>/dev/null"
    initDB="psql -c 'drop database if exists uaa;' -U postgres; psql -c 'create database uaa;' -U postgres; psql -c 'drop user if exists root;' --dbname=uaa -U postgres; psql -c \"create user root with superuser password 'changeme';\" --dbname=uaa -U postgres; psql -c 'show max_connections;' --dbname=uaa -U postgres;"
  elif [ "$db" = "mysql" ]  || [ "$db" = "mysql-5.6" ]; then
    launchDB="(MYSQL_ROOT_PASSWORD=changeme /entrypoint.sh mysqld &> /var/log/mysql-boot.log) &"
    testConnection="echo '\s;' | mysql -h 127.0.0.1 -u root --password='changeme' &>/dev/null"
    initDB="mysql -uroot -pchangeme -e 'drop database if exists uaa;'; mysql -uroot -pchangeme -e 'CREATE DATABASE uaa DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;'; mysql -uroot -pchangeme -e \"SET PASSWORD FOR 'root'@'localhost' = PASSWORD('changeme');\";"
  else
    echo "skipping database"
    return 0
  fi

  echo -n "booting $db"
  eval "$launchDB"
  for _ in $(seq 1 60); do
    set +e
    eval "$testConnection"
    exitcode=$?
    set -e
    if [ $exitcode -eq 0 ]; then
      echo "connection established to $db"
      sleep 1
      eval "$initDB"
      return 0
    fi
    echo -n "."
    sleep 1
  done
  echo "unable to connect to $db"
  exit 1
}
