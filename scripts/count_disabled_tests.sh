#!/bin/bash
#
# Gives counts of Disabled Unit/Integration tests in the project
# Usage: count_disabled_tests.sh [-l]
# -l: List the disabled/ignored tests

#######################################
# main
# Arguments:
#   1 - flag to list the disabled/ignored tests
#######################################
function main() {
  local temp_file
  local search_for
  local total
  local unit_tests_count
  local integration_tests_count

  temp_file=$(mktemp)
  search_for='Disabled'
  find . -type f \( ! -wholename '*/target/*' ! -wholename '*/scripts/*' ! -wholename './node_modules/*' ! -wholename '*/tmp/*' ! -wholename './out/*' ! -wholename '*/.gradle/*' ! -wholename '*/build/*' ! -wholename './.idea/*' ! -wholename './.git/*' \) -exec grep -H -A 1 "@$search_for" {} \; \
    | sed -e "s/^\.\///" \
    | sed "/^--$/d; /\@${search_for}/d" >"$temp_file"

  total=$(wc -l <"$temp_file")
  unit_tests_count=$(cat "$temp_file" | grep -v "IT.java" | wc -l)
  integration_tests_count=$(cat "$temp_file" | grep "IT.java" | wc -l)
  echo "Unit Tests:        $unit_tests_count"
  echo "Integration Tests: $integration_tests_count"
  echo "Total:             $total"

  if [[ "$1" == "-l" ]]; then
    echo
    echo Unit Tests:
    echo
    grep -v "IT.java" "$temp_file" | sed -e 's/\.java-/,/' | sort

    echo
    echo Integration Tests:
    echo
    grep "IT.java" "$temp_file" | sed -e 's/\.java-/,/' | sort
  fi

  rm "$temp_file"
}

main "$@"
