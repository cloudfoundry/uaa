#!/usr/bin/env bash

set -eu
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Number of gradle workers times 5, which was somewhat arbitrary but is sufficient in practice.
# We make extra dbs because a gradle worker ID can exceed the max number of workers.
NUM_OF_DATABASES_TO_CREATE=30

function createDB() {
    true
}


function bootDB {
  db=$1

  if [[ "${db}" = "postgresql" ]]; then
    launchDB="(/docker-entrypoint.sh postgres -c 'max_connections=250' &> /var/log/postgres-boot.log) &"
    testConnection="(! ps aux | grep docker-entrypoint | grep -v 'grep') && psql -h localhost -U postgres -c '\conninfo' &>/dev/null"
    initDB="psql -c 'drop database if exists uaa;' -U postgres; psql -c 'create database uaa;' -U postgres; psql -c 'drop user if exists root;' --dbname=uaa -U postgres; psql -c \"create user root with superuser password 'changeme';\" --dbname=uaa -U postgres; psql -c 'show max_connections;' --dbname=uaa -U postgres;"

    function createDB() {
        DATABASE_NAME="uaa_${1}"
        psql -c "create database $DATABASE_NAME;" -U postgres;
    }


  elif [[ "${db}" = "mysql" ]]  || [[ "${db}" = "mysql-5.6" ]]; then
    launchDB="(MYSQL_DATABASE=uaa MYSQL_ROOT_HOST=127.0.0.1 MYSQL_ROOT_PASSWORD='changeme' bash /entrypoint.sh mysqld &> /var/log/mysql-boot.log) &"
    testConnection="echo '\s;' | mysql -uroot -pchangeme &>/dev/null"
    initDB="mysql -uroot -pchangeme -e 'SET GLOBAL max_connections = 250; ALTER DATABASE uaa DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;';"

    function createDB() {
        DATABASE_NAME="uaa_${1}"
        mysql -uroot -pchangeme -e "CREATE DATABASE ${DATABASE_NAME} DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci";
    }

  elif [[ "${db}" = "percona" ]]; then
    launchDB="bash /entrypoint.sh &> /var/log/mysql-boot.log"
    testConnection="echo '\s;' | mysql &>/dev/null"
    initDB="mysql -e \"CREATE USER 'root'@'127.0.0.1' IDENTIFIED BY 'changeme' ;\";
         mysql -e \"GRANT ALL ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION ;\";
         mysql -e 'FLUSH PRIVILEGES ;';
         mysql -uroot -pchangeme -e 'SET GLOBAL max_connections = 250;';
         mysql -uroot -pchangeme -e 'drop database if exists uaa;';
         mysql -uroot -pchangeme -e 'CREATE DATABASE uaa DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;';
         mysql -uroot -pchangeme -e \"SET PASSWORD FOR 'root'@'localhost' = 'changeme';\";
    "
    function createDB() {
        DATABASE_NAME="uaa_${1}"
        mysql -uroot -pchangeme -e "CREATE DATABASE ${DATABASE_NAME} DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci";
    }

  else
    echo "skipping database"
    return 0
  fi

  echo -n "Booting $db"
  set -x
  eval "$launchDB"
  while true; do
    set +ex
    eval "$testConnection"
    exitcode=$?
    set -e
    if [[ $exitcode -eq 0 ]]; then
      set -x
      echo "Connection established to $db"
      sleep 1
      eval "$initDB"

      for db_id in `seq 1 $NUM_OF_DATABASES_TO_CREATE`; do
        createDB $db_id
      done

      return 0
    fi
    echo -n "."
    sleep 1
  done
}
