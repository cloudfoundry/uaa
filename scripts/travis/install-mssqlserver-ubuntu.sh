#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

#sudo apt-get -y remove mssql-server
#sudo rm -rf /var/opt/mssql/

curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
curl https://packages.microsoft.com/config/ubuntu/16.04/mssql-server.list | sudo tee /etc/apt/sources.list.d/mssql-server.list
curl https://packages.microsoft.com/config/ubuntu/16.04/prod.list | sudo tee /etc/apt/sources.list.d/msprod.list

sudo apt-get -y update
sudo apt-get -y install mssql-server
sudo apt-get -y install mssql-tools

#Start SQL Server and set the base password
sudo SA_PASSWORD=changemeCHANGEME1234! /opt/mssql/bin/sqlservr-setup --accept-eula --set-sa-password --start-service

#Create the uaa database and root user
sqlcmd -S localhost -U SA -P 'changemeCHANGEME1234!' -i $DIR/ms-sql-server-db.sql