#!/bin/bash -e

cd `dirname $0`/..

if [ "$#" -lt 2 ]; then
    echo "Usage: $(basename $0) uaa_release_version uaa_next_dev_version [branch_to_release_from] [branch_to_push_to]"
    exit 1
fi

branch_to_release_from=develop
branch_to_push_to=master

if [ "$#" -ge 3 ]; then
    branch_to_release_from=$3
fi

if [ "$#" -ge 4 ]; then
    branch_to_push_to=$4
fi

echo Deploying and finishing UAA release $1

set -x

git checkout releases/$1
#./gradlew clean artifactoryPublish
git checkout $branch_to_push_to
git merge releases/$1 --no-ff -m "Merge branch 'releases/$1'"
git tag -a $1 -m "$1 release of the UAA"
git push origin $branch_to_push_to --tags

git co $branch_to_release_from
git merge releases/$1 --no-ff -m "Merge branch 'releases/$1' into $branch_to_release_from"
git branch -d releases/$1
./scripts/set-version.sh $2
git commit -am "Bump next $branch_to_release_from version"
git --no-pager diff origin/$branch_to_release_from
git push origin $branch_to_release_from

set +x

echo Artifacts published to Artifactory from releases/$1
echo
echo releases/$1 has been merged into $branch_to_push_to, tagged and pushed
echo
echo releases/$1 has been merged into $branch_to_release_from
echo
echo UAA version bumped to $2 on $branch_to_release_from
