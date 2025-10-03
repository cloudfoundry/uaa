#!/usr/bin/env bash
set -eu

#######################################
# Function to report elapsed time
# Globals:
#   start_time
#######################################
report_elapsed_time() {
  local end_time elapsed_time elapsed_minutes elapsed_seconds

  end_time=$(date +%s)
  elapsed_time=$((end_time - start_time))
  elapsed_minutes=$((elapsed_time / 60))
  elapsed_seconds=$((elapsed_time % 60))

  if [[ "$OSTYPE" == "darwin"* ]]; then
    echo Ended $(date -u -r "$end_time" +"%T%z")
  else
    echo Ended $(date -u -d "@$end_time" +"%T%z")
  fi
  echo "Elapsed time: ${elapsed_minutes} minutes ${elapsed_seconds} seconds"
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
function start_timer() {
  start_time=$(date +%s)
  if [[ "$OSTYPE" == "darwin"* ]]; then
    echo Started $(date -u -r "$start_time" +"%T%z")
  else
    echo Started $(date -u -d "@$start_time" +"%T%z")
  fi

  trap report_elapsed_time EXIT
}
