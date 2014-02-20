#!/bin/bash
mvn tomcat:run --quiet > /dev/null &
echo $! > mvn.pid
sleep 30

