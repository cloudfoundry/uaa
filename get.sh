#!/bin/sh

access_token=`[ -f .access_token ] && cat .access_token`; 

if [ "$1" = "" ]; then
	echo "First argument should be a server path, e.g. localhost:8080/api/photos"
	exit 2;
fi

if (echo $1 | grep -q "\-.*"); then
	echo "Options for curl come after the server path"
	exit 3;
fi

get() {
  location=$1
  shift
  if [ "" = "$access_token" ]; then
      # maybe there is a cookie that identifies us
      # N.B. use -d for request parameters (and curl will switch to POST)
      mkdir -p ~/tmp
      curl -b ~/tmp/cookies.txt -c ~/tmp/cookies.txt -s -L $location $* -H "Accept: application/json; */*"
  else 
      # TODO: check that the json works
      curl -s -L $location  -H "Accept: application/json; */*" -H "Authorization: Bearer $access_token" $*
  fi
}

get $* || echo "Could not connect to $1.  Is the service operating?" && exit 1


