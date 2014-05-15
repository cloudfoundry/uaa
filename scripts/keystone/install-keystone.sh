#!/bin/bash

#ignore these errors - they are for repeatable local builds
ps -ef |grep keystone-all |grep python |awk '{print $2}' | xargs kill -9
sudo rm -rf /etc/keystone
sudo rm -rf /opt/stack

set -e

cd `dirname $0`/../..

set -x



sudo apt-get -qy update
sudo apt-get -qy install git python-pip curl
sudo apt-get -qy install python-dev libevent-dev
sudo apt-get -qy install python-dev libxml2-dev libxslt1-dev libsasl2-dev libsqlite3-dev libssl-dev libldap2-dev libffi-dev
sudo mkdir /opt/stack
sudo chown -R $USER /opt/stack
cd /opt/stack
git clone http://github.com/openstack/keystone.git
cd keystone
sudo pip install -r requirements.txt
sudo pip install -r test-requirements.txt
sudo pip install --upgrade python-keystoneclient
sudo mkdir /etc/keystone
sudo chown -R $USER /etc/keystone
cp -R /opt/stack/keystone/etc/* /etc/keystone/
cd /opt/stack/keystone/bin
./keystone-all &
sleep 3
./keystone-manage db_sync
./keystone-manage pki_setup
export OS_SERVICE_ENDPOINT=http://localhost:35357/v2.0
export OS_SERVICE_TOKEN=ADMIN
keystone service-create --name=keystoneV3 --type=identity --description="Keystone Identity Service V3"
SVC_ID=`keystone service-create --name=keystoneV3 --type=identity --description="Keystone Identity Service V3" |grep " id "|awk '{print $4}'`
keystone endpoint-create --service_id=$SVC_ID --publicurl=http://localhost:5000/v3 --internalurl=http://localhost:5000/v3 --adminurl=http://localhost:35357/v3
keystone user-create --name admin --pass admin
keystone user-create --name marissa --pass koala
keystone user-create --name marissa2 --pass keystone

#curl -X POST -H "Content-Type: application/json" -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"domain":{"name":"Default"},"name":"marissa","password":"koala"}}}}}' -D - http://localhost:5000/v3/auth/tokens