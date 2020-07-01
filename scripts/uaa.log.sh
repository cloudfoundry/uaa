
UAA_LOG=$(grep --text /webapps/uaa.war uaa/build/reports/tests/uaa-server.log | cut -d "[" -f2 | cut -d "]" -f1 | sed 's/webapps\/uaa.war/logs\/uaa.log/')

echo $UAA_LOG

tail -f $UAA_LOG
