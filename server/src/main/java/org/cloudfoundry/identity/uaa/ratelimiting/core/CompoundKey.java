package org.cloudfoundry.identity.uaa.ratelimiting.core;

import lombok.EqualsAndHashCode;
import lombok.Getter;

/**
 * The compound key must immutable and support the hashCode and equals methods as it is used the primary hash key for tracking internal limiters!
 */
@Getter
@EqualsAndHashCode
public final class CompoundKey {
    public static CompoundKey from(String limiterName, String windowType, String callerID) {
        return new CompoundKey( limiterName, windowType, callerID );
    }

    @Override
    public String toString() {
        return limiterName + "|" + windowType + "|" + callerID;
    }

    public String errorString() {
        return "Name: " + limiterName + " Type: " + windowType;
    }

    private final String limiterName;
    private final String windowType;
    private final String callerID;

    private CompoundKey(String limiterName, String windowType, String callerID) {
        this.limiterName = limiterName;
        this.windowType = windowType;
        this.callerID = callerID;
    }
}
