#!/usr/bin/env bash
set -eu

#################################
# create_db
# Placeholder to be overridden per DB type, Creates a database with the name uaa_<number>
# Arguments:
#   $1 - Database number suffix
#################################
function create_db() {
  local database_name="uaa_${1}"
  true
}

#################################
# wait_for_connection
# Waits up to 5 minutes for a database connection to be established
# Globals:
#   db
#   test_connection
# Returns:
#   0, connection established
#   1, timeout
#################################
function wait_for_connection() {
  local i

  for i in {0..100}; do
    if eval "${test_connection}"; then
      echo "Connection established to $db"
      sleep 1
      return 0
    fi
    echo -n "."
    sleep 3
  done

  return 1
}

##################################
# initialize_db
# Initializes the database, retrying with exponential backoff
# Globals:
#   init_db
# Returns:
#   0 if DB initialized, 1 if all attempts fail
##################################
function initialize_db() {
  local number_attempts=10
  local attempt
  for attempt in $(seq 1 "${number_attempts}"); do
    echo "Initializing DB, attempt ${attempt} of ${number_attempts}"
    if eval "${init_db}"; then
      echo "${db} DB initialized"
      return 0
    fi
    if [[ "${attempt}" == "${number_attempts}" ]]; then
      echo 'error initializing the DB, aborting'
      return 1
    fi
    local wait_time="$(( (2 ** (attempt - 1)) < 32 ? (2 ** (attempt - 1)) : 32 ))"
    echo "Error initializing the DB, retrying in ${wait_time} seconds"
    sleep "${wait_time}"

  done
}

##################################
# create_databases
# Creates multiple databases to support parallel tests
# See docs/testing.md, sections on "test pollution" and "parallelism"
# Globals:
#   create_db
##################################
function create_databases() {
  local num_of_databases_to_create=24
  echo "Creating $num_of_databases_to_create databases to support parallel tests"
  local db_id
  for db_id in $(seq 1 "${num_of_databases_to_create}"); do
    create_db "${db_id}"
    sleep 1
  done

  return 0
}

##################################
# print_database_logs
# Prints the database boot logs if they exist
# Globals:
#   boot_log_location
##################################
function print_database_logs() {
  if [ -f "${boot_log_location}" ]; then
    echo
    echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
    echo "Database boot logs:"
    echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
    cat "$boot_log_location"
  else
    echo "No Database boot logs were found at ${boot_log_location}"
  fi
}

##################################
# bootDB
# Boots the specified database, initializes it, and creates multiple databases
# Arguments:
#   $1 - Database type (e.g., postgresql, mysql, percona)
# Returns:
#   Exits with code 1 on failure
##################################
function boot_db() {
  db=$1
  local db_password="changeme"
  local launch_db

  if [[ "${db}" = "postgresql" ]]; then
    boot_log_location="/var/log/postgres-boot.log"
    launch_db="(POSTGRES_HOST_AUTH_METHOD=trust docker-entrypoint.sh postgres -c 'max_connections=250' &> ${boot_log_location}) &"
    test_connection="psql -h localhost -U postgres -c '\conninfo' &>/dev/null"
    init_db="psql -c 'drop database if exists uaa;' -h localhost -U postgres
      psql -c 'create database uaa;' -h localhost -U postgres;
      psql -c 'drop user if exists root;' -h localhost --dbname=uaa -U postgres;
      psql -c \"create user root with superuser password '${db_password}';\" -h localhost --dbname=uaa -U postgres;
      psql -c 'show max_connections;' -h localhost --dbname=uaa -U postgres;"

    # Override create_db function for PostgreSQL
    function create_db() {
      local database_name="uaa_${1}"
      echo "Creating PostgreSQL database: ${database_name}"
      psql -c "create database ${database_name};" -h localhost -U postgres
    }

  elif [[ "${db}" = "mysql" ]]; then
    boot_log_location="/var/log/mysql-boot.log"
    # Add for more info: --general-log=1 --general-log-file=/var/lib/mysql/general.log
    launch_db="(export MYSQL_DATABASE=uaa; export MYSQL_ROOT_HOST=127.0.0.1; export MYSQL_ROOT_PASSWORD=${db_password}; bash /entrypoint.sh mysqld --log-error-verbosity=3 &> ${boot_log_location}) &"
    test_connection="mysqladmin ping -v --host 127.0.0.1 --user=root --password=${db_password} &>/dev/null"
    init_db="mysql -v --host 127.0.0.1 --user=root --password=${db_password} -e \"CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '${db_password} '; GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;\"
              mysql -v --host 127.0.0.1 --user=root --password=${db_password} -e 'SET GLOBAL max_connections = 250; ALTER DATABASE uaa DEFAULT CHARACTER SET utf8mb4;';"

    # Override create_db function for MySQL
    function create_db() {
      local database_name="uaa_${1}"
      echo "Creating MySQL database: ${database_name}"
      mysql --host 127.0.0.1 --user=root --password="${db_password}" -e "CREATE DATABASE ${database_name} DEFAULT CHARACTER SET utf8mb4"
    }

  elif [[ "${db}" = "percona" ]]; then
    boot_log_location="/var/log/mysql-boot.log"
    launch_db="bash /entrypoint.sh &> ${boot_log_location}"
    test_connection="echo '\s;' | mysql &>/dev/null"
    init_db="mysql -e \"CREATE USER 'root'@'127.0.0.1' IDENTIFIED BY '${db_password}' ;\";
           mysql -e \"GRANT ALL ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION ;\";
           mysql -e 'FLUSH PRIVILEGES ;';
           mysql --user=root --password=${db_password} -e 'SET GLOBAL max_connections = 250;';
           mysql --user=root --password=${db_password} -e 'drop database if exists uaa;';
           mysql --user=root --password=${db_password} -e 'CREATE DATABASE uaa DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;';
           mysql --user=root --password=${db_password} -e \"SET PASSWORD FOR 'root'@'localhost' = '${db_password}';\";
      "

    # Override create_db function for Percona
    function create_db() {
      local database_name="uaa_${1}"
      echo "Creating Percona database: ${database_name}"
      mysql --user=root --password="${db_password}" -e "CREATE DATABASE ${database_name} DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci"
    }

  else
    echo "skipping database"
    return 0
  fi

  # Start DB
  echo -n "Starting ${db} database: "
  eval "${launch_db}"

  if ! wait_for_connection; then
    print_database_logs
    exit 1
  fi
  if ! initialize_db; then
    print_database_logs
    exit 2
  fi
  create_databases
}
