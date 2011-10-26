#!/bin/sh

if [ ! -f .access_token ]; then 
    echo "No access token available.  Please login first."
    exit 1
fi

access_token=`cat .access_token`; 

post() {
  location=$1
  shift
  curl -X POST -s -L -H "Accept: application/json" $location -H "Authorization: Bearer $access_token" $*
}

if [ ! "$access_token" = "" ]; then
	post $* || echo "Could not connect.  Is the service operating?" && exit 1
else
    echo "No access token available.  Login first."
    exit 2
fi
