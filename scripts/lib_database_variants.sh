#!/usr/bin/env bash
set -eu

#################################
# parse_db_name
# Parses the DB image name and sets global variables accordingly
# Sets Docker image name, Profile Name, and DB name
# Arguments:
#   $1 - The database variant (e.g., postgresql-17, mysql-8.4, defaults to: hsqldb)
# Globals:
#   DB - The database type (e.g., postgresql, mysql, hsqldb)
#   PROFILE_NAME - The profile name to use for tests (usually same as DB)
#   DOCKER_IMAGE - The full Docker image to use (if not already set)
# #################################
function parse_db_name() {

  # Set default Docker image name, Profile Name, and DB name, may be overridden below
  # Default to hsqldb if no argument is provided
  local db_image_name="${1:-hsqldb}"

  # Extract the DB type (the part before any dash version)
  DB="${db_image_name%%-*}"
  PROFILE_NAME="${db_image_name%%-*}"

  case "${db_image_name}" in
    # PostgreSQL versions are named after their major version

    # Consider no version label to be the latest LTS version
    postgresql)
      db_image_name=postgresql-17
      ;;

    # Fully specified versions pass through
    postgresql-18|postgresql-17|postgresql-16|postgresql-15|postgresql-11)
      ;;

    #### MySQL versions ####
    # MySQL versions are named after their major.minor version
    # Major versions are aliases to the latest minor version in that major series

    # Consider no version label to be the latest LTS version
    mysql)
      db_image_name=mysql-8.4
      ;;

    # mysql-9 floats until it becomes the LTS
    mysql-9)
      ;;

    # mysql-8 should be an alias to the latest 8.x version, but currently keeping as the last debian-based mysql-8.0 image
    mysql-8)
      #db_image_name=mysql-8.4
      ;;

    # Treat mysql-5 as an alias to mysql-5.7
    mysql-5)
      db_image_name=mysql-5.7
      ;;

    # Fully specified versions pass through
    mysql-8.4|mysql-8.0|mysql-5.7)
      ;;

    #### Other Databases ####

    # we don't have a container image for hsqldb, and can use any image
    hsqldb)
      db_image_name=postgresql-17
      ;;

    percona|percona-8)
      PROFILE_NAME=mysql
      ;;

    *)
      echo $"ERROR: $1 is not a known database type. Supported types are: hsqldb, percona, postgresql, mysql, and their versions."
      exit 1
  esac

  if [[ -z "${DOCKER_IMAGE+x}" ]]; then
    DOCKER_IMAGE="cfidentity/uaa-${db_image_name}"
  fi
}

#######################################
# database_port
# Returns the default port for the specified database variant
# Arguments:
#   $1 - The database variant (e.g., postgresql-17, mysql-8.4, defaults to: hsqldb)
#######################################
function database_port() {
  local db_image_name="${1:-hsqldb}"
  local db="${db_image_name%%-*}"
  case "${db}" in
    postgresql)
      echo 5432
      ;;
    mysql|percona)
      echo 3306
      ;;
    hsqldb)
      # the default port is 9001, if running in server mode
      echo 9001
      ;;
    *)
      echo $"ERROR: $1 is not a known database type. Supported types are: hsqldb, percona, postgresql, mysql."
      exit 1
  esac
}