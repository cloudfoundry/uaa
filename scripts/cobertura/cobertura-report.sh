#!/bin/bash

cd `dirname $0`/../..

set -e

UAA_CLASSPATH=`mvn -pl uaa dependency:build-classpath -P coverage | grep -v "\[" | tail -n 1`

set -x

java -cp $UAA_CLASSPATH net.sourceforge.cobertura.merge.Main common/cobertura.ser
java -cp $UAA_CLASSPATH net.sourceforge.cobertura.merge.Main scim/cobertura.ser
java -cp $UAA_CLASSPATH net.sourceforge.cobertura.merge.Main uaa/cobertura.ser

java -cp $UAA_CLASSPATH net.sourceforge.cobertura.reporting.Main --destination target/site/cobertura --format xml common/target/classes scim/target/classes uaa/target/classes
