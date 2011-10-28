#!/bin/sh

if [ "$1" = "" ]; then
	echo "First argument should be an auth server path, e.g. localhost:8080/auth"
	exit 2;
fi

# if (echo $1 | grep -q "\-.*"); then
#   echo "Options come after the server path"
#   exit 3;
# fi

ROOT=$1

echo "\nInvoking /login_info endpoint...\n"

response=`curl -s -H "Accept: application/json" $ROOT/login_info`

echo "Response $response\n"

shift
CLIENT=vmc
REDIRECT_URI="vmc://implicit_grant"
SCOPE=read

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
		SCOPE=$1
		shift
	fi
done

echo "Username (marissa): \c"
read username
echo "Password (koala):\c"
read password

if [ "$username" = "" ]; then username=marissa; fi
if [ "$password" = "" ]; then password=koala; fi

# Request token from /authorize endpoint
# TODO: This needs to be changed to a POST
authorizeUrl=$ROOT/oauth/authorize

credentials="{\"username\":\"$username\",\"password\":\"$password\"}"

echo "\nInvoking /authorize endpoint with credentals $credentials, client=$CLIENT and scope=$SCOPE\n"

response=`curl --write-out "Location: %{redirect_url}" -s -S -G --data-urlencode "credentials=$credentials" -d "client_id=$CLIENT" -d "response_type=token" -d "scope=$SCOPE" --data-urlencode "redirect_uri=$REDIRECT_URI" -H "Accept: application/json" $authorizeUrl`

echo "$response\n"

echo $response | grep access_token | sed -e 's/.*access_token=//' > .access_token

if [ "`cat .access_token`" != "" ]; then echo "Successfully authenticated"; exit 0; fi

echo "Failed to authenticate: "$response
exit 1

