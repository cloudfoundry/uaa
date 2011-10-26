#!/bin/sh

if [ "$1" = "" ]; then
	echo "First argument should be an auth server path, e.g. localhost:8080/auth"
	exit 2;
fi

if (echo $1 | grep -q "\-.*"); then
	echo "Options come after the server path"
	exit 3;
fi

ROOT=$1
shift

if [ -f .access_token ]; then 
	access_token=`cat .access_token`; 
fi

get() {
  location=$1
  shift
  curl -s -L -H "Accept: application/json" $location -H "Authorization: Bearer $access_token" $*
}

if [ ! "$access_token" = "" ]; then
	response=`get $ROOT/logout.do`
fi

rm -f .access_token
