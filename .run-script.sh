#!/bin/bash
mvn tomcat:run --quiet &
echo $! > mvn.pid
sleep 30

