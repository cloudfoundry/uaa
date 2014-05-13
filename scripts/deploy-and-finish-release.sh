#!/bin/bash -e

cd `dirname $0`/..

if [ "$#" -ne 2 ]; then
    echo "Usage: $(basename $0) uaa_release_version uaa_next_dev_version"
fi

echo Deploying and finishing UAA release $1

set -x

git checkout releases/$1
mvn deploy -DskipTests=true
git checkout master
git merge releases/$1 --no-ff
git tag -a $1 -m "$1 release of the UAA"
git push origin master
git push origin --tags
git co develop
git merge releases/$1 --no-ff
git branch -d releases/$1
./scripts/set-version.sh $2
git commit -am "Bump next developer version"


set +x

echo Maven deploy made from releases/$1
echo
echo releases/$1 merged into master, tagged and pushed
echo
echo releases/$1 back merged into develop
echo
echo UAA version bumped to $2 on develop
echo
echo Check the dev versions, ammend if necessary, and push the changes
