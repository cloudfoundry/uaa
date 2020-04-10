package org.cloudfoundry.identity.uaa.util;


import java.util.Date;

public interface TimeService {
    default long getCurrentTimeMillis() {
        return System.currentTimeMillis();
    }

    default Date getCurrentDate() { return new Date(getCurrentTimeMillis()); }
}
