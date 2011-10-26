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
CLIENT=vmc
SCOPE=

if [ -f .access_token ]; then 
	access_token=`cat .access_token`; 
fi

OPTIONS=

while (echo "$1" | grep -q "\-.*"); do

	if [ -n "$1" -a "$1" = "-client" ]; then
		shift
		CLIENT=$1
		shift
	elif [ -n "$1" -a "$1" = "-scope" ]; then
		shift
		SCOPE=\&scope=$1
		shift
	else
		OPTIONS=$1
		shift
		while [ "$1" != "" ] && ! (echo "$1" | grep -q "\-.*"); do
			OPTIONS=$OPTIONS $1
			shift
		done
	fi

done

get() {
  location=$1
  shift
  if [ "$access_token" = "" ]; then
	  curl -s -L -H "Accept: application/json" $location $*
  else
	  curl -s -L -H "Accept: application/json" $location -H "Authorization: Bearer $access_token" $*
  fi
}

response=`get $ROOT $*`

echo $response | grep -q "logged in"
if [ $? = 0 ]; then 
	echo "Already logged in"
	exit 0
fi

# Not logged in

echo -n "Username (dsyer@vmware.com): "
read username
echo -n "Password: "
read password

if [ "$username" = "" ]; then username=dsyer@vmware.com; fi
if [ "$password" = "" ]; then 
	echo "No password provided, please try again"
	exit 1
fi

response=`get $ROOT/oauth/token?grant_type=password\&client_id=$CLIENT\&username="$username"\&password="$password"\&response_type=code$SCOPE $*`
echo $response | grep access_token | sed -e 's/.*access_token\": \"//' -e 's/\",.*//' > .access_token

if [ "`cat .access_token`" != "" ]; then echo "Successfully authenticated"; exit 0; fi

echo "Failed to authenticate: "$response
exit 1

