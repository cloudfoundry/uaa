#!/bin/bash -e

cd `dirname $0`/..

if [ "$#" -lt 2 ]; then
    echo "Usage: $(basename $0) uaa_release_version uaa_next_dev_version [branch_to_release_from]"
    exit 1
fi

branch_to_release_from=develop

if [ "$#" -eq 3 ]; then
    branch_to_release_from=$3
fi

echo Deploying and finishing UAA release $1

set -x

git checkout releases/$1
./gradlew clean artifactoryPublish
git checkout master
git merge releases/$1 --no-ff -m "Merge branch 'releases/$1'"
git tag -a $1 -m "$1 release of the UAA"
git push origin master --tags

git co $branch_to_release_from
git merge releases/$1 --no-ff -m "Merge branch 'releases/$1' into develop"
git branch -d releases/$1
./scripts/set-version.sh $2
git commit -am "Bump next developer version"
git --no-pager diff origin/$branch_to_release_from
git push origin $branch_to_release_from

set +x

echo Artifacts published to Artifactory from releases/$1
echo
echo releases/$1 merged into master, tagged and pushed
echo
echo releases/$1 back merged into develop
echo
echo UAA version bumped to $2 on develop
