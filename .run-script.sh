#!/bin/bash



if [ "$1" = "restart" ]; then
  target/tomcat/bin/shutdown.sh -force
  rm -f $CATALINA_PID  
elif [ "$1" = "stop" ]; then
  target/tomcat/bin/shutdown.sh -force
  RETVAL=$?
  rm -f $CATALINA_PID
  exit 0
fi

echo "spring_profiles: $TESTENV" > target/tomcat/webapps/uaa/WEB-INF/classes/uaa.yml
target/tomcat/bin/startup.sh

SLEEP_TIME=120
echo "Sleeping $SLEEP_TIME seconds or until Tomcat has started."
while [ $SLEEP_TIME -gt 0 ]; do
        echo -n ".${SLEEP_TIME}"
        sleep 1
        let SLEEP_TIME=SLEEP_TIME-1
        grep "INFO: Starting ProtocolHandler" $CATALINA_OUT 2>&1 >/dev/null
        GREP_EXIT=$?
        if [ $GREP_EXIT -eq 0 ]
        then
          SLEEP_TIME=0
        fi
        ps -p `cat $CATALINA_PID` 2>&1 >/dev/null
        PS_EXIT_VALUE=$?
        if [ $PS_EXIT_VALUE -ne 0 ]
        then
            echo ""
            echo "Tomcat no longer running."
            SLEEP_TIME=0
        fi
done
ps -p `cat $CATALINA_PID`
EXIT_VALUE=$?
echo "Tomcat running status:$EXIT_VALUE"
exit $EXIT_VALUE
