package org.cloudfoundry.identity.uaa.ratelimiting.util;

public class IntUtils {
    public static Integer parseNoException( String source, Integer defaultOnEmpty ) {
        try {
            return parse( source, defaultOnEmpty );
        }
        catch ( NumberFormatException e ) {
            return null;
        }
    }

    public static Integer parse( String source, Integer defaultOnEmpty ) {
        source = StringUtils.normalizeToEmpty( source );
        return source.isEmpty() ? defaultOnEmpty : Integer.valueOf( Integer.parseInt( source ) );
    }
}
