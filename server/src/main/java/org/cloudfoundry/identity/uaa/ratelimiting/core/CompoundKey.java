package org.cloudfoundry.identity.uaa.ratelimiting.core;

import lombok.EqualsAndHashCode;
import lombok.Getter;

@Getter
@EqualsAndHashCode
public final class CompoundKey {
    public static CompoundKey from( String limiterName, String windowType, String callerID ) {
        return new CompoundKey( limiterName, windowType, callerID );
    }

    @Override
    public String toString() {
        return limiterName + "|" + windowType + "|" + callerID;
    }

    private final String limiterName;
    private final String windowType;
    private final String callerID;

    private CompoundKey( String limiterName, String windowType, String callerID ) {
        this.limiterName = limiterName;
        this.windowType = windowType;
        this.callerID = callerID;
    }
}
