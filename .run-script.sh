#!/bin/bash

export MAVEN_OPTS="-Xss8192k"
mvn tomcat7:run -Pintegration $1 --quiet > /tmp/tomcat.log 2>&1 &
echo $! > mvn.pid

SLEEP_TIME=120
echo "Sleeping $SLEEP_TIME seconds or until Tomcat has started."
while [ $SLEEP_TIME -gt 0 ]; do
        echo -n ".${SLEEP_TIME}"
        sleep 1
        let SLEEP_TIME=SLEEP_TIME-1
        grep "INFO: Starting ProtocolHandler" /tmp/tomcat.log 2>&1 >/dev/null
        GREP_EXIT=$?
        if [ $GREP_EXIT -eq 0 ]
        then
          SLEEP_TIME=0
        fi
        ps -p `cat mvn.pid` 2>&1 >/dev/null
        PS_EXIT_VALUE=$?
        if [ $PS_EXIT_VALUE -ne 0 ]
        then
            echo ""
            echo "Tomcat no longer running."
            SLEEP_TIME=0
        fi
done
ps -p `cat mvn.pid`
EXIT_VALUE=$?
echo "Tomcat running status:$EXIT_VALUE"
if [ $EXIT_VALUE -ne 0 ]
then
    cat /tmp/tomcat.log
fi
rm -f /tmp/tomcat.log
exit $EXIT_VALUE
