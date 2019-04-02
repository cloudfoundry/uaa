package org.cloudfoundry.identity.uaa.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UaaDatabaseName {

    private static Logger logger = LoggerFactory.getLogger(UaaDatabaseName.class);


    private static final String UAA_DB_NAME = "uaa";

    private final String gradleWorkerId;

    public UaaDatabaseName(String gradleWorkerId) {
        this.gradleWorkerId = gradleWorkerId;
    }

    public String getName() {
        logger.error("AAAAAA gradleWorkerId: {}", gradleWorkerId);

        if (gradleWorkerId == null) {
            return UAA_DB_NAME;
        }

        return UAA_DB_NAME + "_" + gradleWorkerId;
    }
}
