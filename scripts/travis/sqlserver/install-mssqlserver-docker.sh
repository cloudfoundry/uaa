#!/bin/bash -e

#sudo apt-get -y update
#sudo apt-get -y install docker.io
#sudo gpasswd -a $(whoami) docker
#sudo service docker restart

sudo docker run -e 'ACCEPT_EULA=Y' -e 'SA_PASSWORD=changemeCHANGEME1234!' -p 1433:1433 -d microsoft/mssql-server-linux
