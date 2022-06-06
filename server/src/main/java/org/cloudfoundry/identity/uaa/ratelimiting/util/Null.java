package org.cloudfoundry.identity.uaa.ratelimiting.util;

public class Null {
    public static <T> T errorOn( String what, T value ) {
        if ( value != null ) {
            return value;
        }
        throw new Error( "No '" + what + "' provided -- coding error" );
    }

    public static <T> T defaultOn( T value, T defaultValue ) {
        return (value != null) ? value : defaultValue;
    }

    public static int countNonNull( Object... objects ) {
        int count = 0;
        if ( objects != null ) {
            for ( Object o : objects ) {
                if ( o != null ) {
                    count++;
                }
            }
        }
        return count;
    }
}
