#!/bin/bash
#
# Gives counts of Disabled/Ignored Unit/Integration tests in the project
# Usage: count-disabled-tests.sh [-l]
# -l: List the disabled/ignored tests

function main() {
  local tempFile
  local searchFor
  local disableCount
  local ignoreCount
  local total
  local unitTestsCount
  local integrationTestsCount

  tempFile=$(mktemp)
  searchFor='Disabled'
  find . -type f \( ! -wholename '*/target/*' ! -wholename './node_modules/*' ! -wholename '*/tmp/*' ! -wholename './out/*' ! -wholename '*/.gradle/*' ! -wholename '*/build/*' ! -wholename './.idea/*' ! -wholename './.git/*' \) -exec grep -H -A 1 "@$searchFor" {} \; | sed -e "s/^\.\///" | sed "/^--$/d; /\@${searchFor}/d" >"$tempFile"
  disableCount=$(wc -l <"$tempFile")

  searchFor='Ignore'
  find . -type f \( ! -wholename '*/target/*' ! -wholename './node_modules/*' ! -wholename '*/tmp/*' ! -wholename './out/*' ! -wholename '*/.gradle/*' ! -wholename '*/build/*' ! -wholename './.idea/*' ! -wholename './.git/*' \) -exec grep -H -A 1 "@$searchFor" {} \; | sed -e "s/^\.\///" | sed "/^--$/d; /\@${searchFor}/d" >>"$tempFile"
  total=$(wc -l <"$tempFile")
  ignoreCount=$(($total - $disableCount))

  echo "Disabled: $disableCount"
  echo "Ignored:  $ignoreCount"
  echo "Total:    $total"
  echo

  unitTestsCount=$(cat "$tempFile" | grep -v "IT.java" | wc -l)
  integrationTestsCount=$(cat "$tempFile" | grep "IT.java" | wc -l)
  echo "Unit Tests:        $unitTestsCount"
  echo "Integration Tests: $integrationTestsCount"
  echo "Total:             $total"

  if [[ "$1" -eq "-l" ]]; then
    echo
    echo Unit Tests:
    echo
    cat "$tempFile" | grep -v "IT.java" | sort

    echo
    echo Integration Tests:
    echo
    cat "$tempFile" | grep "IT.java" | sort

  fi

  rm "$tempFile"
}

main "$@"
