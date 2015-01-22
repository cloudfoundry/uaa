#!/bin/bash -e

cd `dirname $0`/..


if [ "$#" -lt 1 ]; then
    echo "Usage: $(basename $0) uaa_release_version [branch_to_release_from]"
    exit
fi

branch_to_release_from=develop

if [ "$#" -eq 2 ]; then
    branch_to_release_from=$2
fi

echo Creating UAA release $1

set -x

if [[ -n $(git status -s --ignored) ]]; then
    echo "ERROR: Release must be performed from a fresh clone of the repository."
    exit 1
fi

git checkout $branch_to_release_from
git checkout -b releases/$1
./scripts/set-version.sh $1
git commit -am "Bump release version to $1"
git push --set-upstream origin releases/$1

set +x

echo Release branch created from develop branch
echo
echo Check the version number changes and ammend if necessary
echo
echo Deploy and finish the release with deploy-and-finish-release.sh