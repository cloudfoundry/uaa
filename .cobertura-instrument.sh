#!/bin/bash

cd `dirname $0`

set -e

mvn -pl common dependency:build-classpath -P coverage --quiet
mvn -pl scim dependency:build-classpath -P coverage --quiet
mvn -pl uaa dependency:build-classpath -P coverage --quiet

COMMON_CLASSPATH=`mvn -pl common dependency:build-classpath -P coverage | grep -v "\[" | tail -n 1`
SCIM_CLASSPATH=`mvn -pl scim dependency:build-classpath -P coverage | grep -v "\[" | tail -n 1`
UAA_CLASSPATH=`mvn -pl uaa dependency:build-classpath -P coverage | grep -v "\[" | tail -n 1`

set -x

java -cp $COMMON_CLASSPATH net.sourceforge.cobertura.instrument.Main common/target/classes --ignore CoverageController
java -cp $SCIM_CLASSPATH net.sourceforge.cobertura.instrument.Main scim/target/classes
java -cp $UAA_CLASSPATH net.sourceforge.cobertura.instrument.Main uaa/target/classes
