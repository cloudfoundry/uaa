#!/bin/bash
mvn tomcat:run --quiet > /dev/null &
echo $! > mvn.pid
sleep 30
ps -p `cat mvn.pid`
EXIT_VALUE=$?
echo "Tomcat running status:$EXIT_VALUE"
exit $EXIT_VALUE

